import type { PluginLogger } from '../sdk';
import { nextOccurrence, parseCron } from './parser';
import type { ScheduleStore } from './store';
import { formatDuration, formatLocalDateTime } from './time';
import type { CronPluginConfig, ScheduleItem } from './types';

// setTimeout overflows (fires immediately) past ~24.8 days, so a far-off item
// is reached by re-arming at most this far ahead.
const MAX_TIMER_MS = 3_600_000;
// Gives core time to finish startup (seeding the current context) before a
// catch-up fire is published.
export const STARTUP_DELAY_MS = 5_000;
// A recurring occurrence later than this was missed (restart, suspend) and is
// skipped rather than fired late. Timer jitter stays far below it.
export const ON_TIME_TOLERANCE_MS = 120_000;
const PUBLISH_RETRY_MS = 60_000;

export interface SchedulerDeps {
  store: ScheduleStore;
  config: CronPluginConfig;
  isEnabled(chatId: string): boolean;
  publish(chatId: string, options: { kind: string; text: string; wake: boolean }): Promise<void> | void;
  log: PluginLogger;
}

export interface Scheduler {
  start(): void;
  /** Recomputes the timer after items changed. */
  rearm(): void;
  stop(): void;
}

export const buildFireText = (item: ScheduleItem, latenessMs: number): string => {
  const late = latenessMs > ON_TIME_TOLERANCE_MS ? ` (${formatDuration(latenessMs)} late)` : '';
  const recurring = item.kind === 'cron' ? `, recurring "${item.spec}"` : '';
  return `Your own scheduled wake-up fired${late}. You set it yourself on ${formatLocalDateTime(item.createdAtMs)}${recurring}; note to self: "${item.note}". It was your own decision, so it is a reason to act unless the moment has clearly passed; if it has, staying silent is fine.`;
};

export const createScheduler = (deps: SchedulerDeps): Scheduler => {
  const { store, config, log } = deps;
  const graceMs = config.lateGraceHours * 3_600_000;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = true;
  let ticking = false;
  let notBeforeMs = 0;

  const earliestDueMs = (): number | undefined => {
    let earliest: number | undefined;
    for (const chatId of store.chatIds()) {
      if (!deps.isEnabled(chatId)) continue;
      for (const item of store.list(chatId)) {
        if (earliest === undefined || item.nextFireAtMs < earliest) earliest = item.nextFireAtMs;
      }
    }
    return earliest;
  };

  const arm = (): void => {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (stopped || ticking) return; // a running tick re-arms when it ends
    const due = earliestDueMs();
    if (due === undefined) return;
    const now = Date.now();
    const delay = Math.min(Math.max(due - now, notBeforeMs - now, 0), MAX_TIMER_MS);
    timer = setTimeout(() => void tick(), delay);
    timer.unref();
  };

  const replaceItem = (chatId: string, id: string, next: ScheduleItem | undefined): void => {
    const items = store.list(chatId);
    store.save(chatId, next
      ? items.map(item => item.id === id ? next : item)
      : items.filter(item => item.id !== id));
  };

  const processItem = async (chatId: string, id: string, now: number): Promise<void> => {
    const item = store.list(chatId).find(i => i.id === id);
    if (!item || item.nextFireAtMs > now) return;
    const lateness = now - item.nextFireAtMs;
    const logFields = { chatId, scheduleId: id, kind: item.kind, latenessMs: lateness };

    if (item.kind === 'once') {
      if (lateness > graceMs) {
        log.withFields(logFields).warn('Dropping one-shot schedule that is overdue beyond lateGraceHours');
        replaceItem(chatId, id, undefined);
        return;
      }
    } else if (lateness > ON_TIME_TOLERANCE_MS) {
      const next = nextOccurrence(parseCron(item.spec), now);
      log.withFields(logFields).log('Skipping missed occurrences of recurring schedule');
      replaceItem(chatId, id, next === undefined ? undefined : { ...item, nextFireAtMs: next });
      return;
    }

    // Publish first, then advance: a crash in between repeats a reminder
    // instead of losing it.
    await deps.publish(chatId, { kind: 'cron', text: buildFireText(item, lateness), wake: true });
    log.withFields(logFields).log('Schedule fired');

    if (item.kind === 'once') {
      replaceItem(chatId, id, undefined);
      return;
    }
    const next = nextOccurrence(parseCron(item.spec), now);
    replaceItem(chatId, id, next === undefined ? undefined : { ...item, lastFiredAtMs: now, nextFireAtMs: next });
  };

  const tick = async (): Promise<void> => {
    timer = undefined;
    ticking = true;
    try {
      const now = Date.now();
      for (const chatId of store.chatIds()) {
        if (!deps.isEnabled(chatId)) continue; // items of a disabled chat are kept untouched
        const dueIds = store.list(chatId).filter(i => i.nextFireAtMs <= now).map(i => i.id);
        for (const id of dueIds) {
          try {
            await processItem(chatId, id, now);
          } catch (error) {
            // Keep the item; retry after a pause instead of spinning on a due item.
            log.withFields({ chatId, scheduleId: id }).withError(error).error('Schedule fire failed');
            notBeforeMs = Date.now() + PUBLISH_RETRY_MS;
          }
        }
      }
    } finally {
      ticking = false;
      arm();
    }
  };

  return {
    start() {
      stopped = false;
      notBeforeMs = Date.now() + STARTUP_DELAY_MS;
      arm();
    },
    rearm: arm,
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = undefined;
    },
  };
};
