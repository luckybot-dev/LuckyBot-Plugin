import { randomUUID } from 'node:crypto';

import * as v from 'valibot';

import type { PluginTool, PluginToolResult } from '../sdk';
import { CronParseError, minGapMs, nextOccurrence, parseCron } from './parser';
import type { Scheduler } from './scheduler';
import type { ScheduleStore } from './store';
import { formatLocalDateTime, parseLocalDateTime } from './time';
import {
  MAX_NOTE_CHARS,
  MAX_REASON_CHARS,
  MIN_LEAD_MS,
  type CronPluginConfig,
  type ScheduleItem,
} from './types';

const DAY_MS = 86_400_000;

const ScheduleInputSchema = v.object({
  at: v.optional(v.string()),
  cron: v.optional(v.string()),
  note: v.string(),
  reason: v.optional(v.string()),
});

const CancelInputSchema = v.object({ id: v.string() });

const result = (payload: Record<string, unknown>): PluginToolResult => ({
  content: JSON.stringify(payload),
  requiresFollowUp: true,
});

const failure = (error: string): PluginToolResult => result({ error });

const oneLine = (text: string): string => text.replace(/\s+/g, ' ').trim();

const describeItem = (item: ScheduleItem) => ({
  id: item.id,
  kind: item.kind,
  ...(item.kind === 'cron' ? { cron: item.spec } : {}),
  next_fire: formatLocalDateTime(item.nextFireAtMs),
  note: item.note,
  ...(item.lastFiredAtMs === undefined ? {} : { last_fired: formatLocalDateTime(item.lastFiredAtMs) }),
});

export interface CronToolDeps {
  chatId: string;
  store: ScheduleStore;
  scheduler: Scheduler;
  config: CronPluginConfig;
}

export const createCronTools = ({ chatId, store, scheduler, config }: CronToolDeps): PluginTool[] => {
  const limits = `Limits: at most ${config.maxActivePerChat} active schedules in this chat; a first fire at least 1 minute ahead and within ${config.maxHorizonDays} days; recurring (cron) schedules may not fire more often than every ${config.minRecurringIntervalMin} minutes. Times are the deployment's local time, the same clock as the chatlog timestamps.`;

  const scheduleWakeup: PluginTool = {
    name: 'schedule_wakeup',
    description: `Schedule a future wake-up for yourself in this chat. Give exactly one of \`at\` (one-off local time, "YYYY-MM-DD HH:MM") or \`cron\` (5-field expression "minute hour day-of-month month day-of-week", local time). \`note\` is what you want to do or say when it fires, in your own words, at most ${MAX_NOTE_CHARS} characters; it appears in the chat context, so keep it free of anything private. \`reason\` is optional and goes only to the audit log (for example whose suggestion you weighed). Firing only wakes you; you can still stay silent then. ${limits}`,
    parameters: {
      type: 'object',
      properties: {
        at: { type: 'string', description: 'One-off local date-time, "YYYY-MM-DD HH:MM".' },
        cron: { type: 'string', description: '5-field cron expression in local time, e.g. "0 9 * * 1-5".' },
        note: { type: 'string', description: 'What to do or say when it fires. Visible in the chat context.' },
        reason: { type: 'string', description: 'Optional audit-log reason; not shown in the chat.' },
      },
      required: ['note'],
    },
    execute: input => {
      const parsed = v.safeParse(ScheduleInputSchema, input);
      if (!parsed.success) return failure(`Invalid input: ${parsed.issues.map(i => i.message).join('; ')}`);
      const { at, cron } = parsed.output;
      const note = oneLine(parsed.output.note);
      const reason = parsed.output.reason === undefined ? undefined : oneLine(parsed.output.reason);

      if ((at === undefined) === (cron === undefined)) return failure('Give exactly one of `at` or `cron`.');
      if (note === '') return failure('`note` must not be empty.');
      if (note.length > MAX_NOTE_CHARS) return failure(`\`note\` is ${note.length} characters; the limit is ${MAX_NOTE_CHARS}.`);
      if (reason !== undefined && reason.length > MAX_REASON_CHARS) return failure(`\`reason\` is too long (limit ${MAX_REASON_CHARS}).`);

      const items = store.list(chatId);
      if (items.length >= config.maxActivePerChat) {
        return failure(`This chat already has ${items.length} active schedules (limit ${config.maxActivePerChat}). Cancel one first with cancel_schedule.`);
      }

      const now = Date.now();
      const horizonEnd = now + config.maxHorizonDays * DAY_MS;
      let kind: ScheduleItem['kind'];
      let spec: string;
      let nextFireAtMs: number;

      if (at !== undefined) {
        const atMs = parseLocalDateTime(at);
        if (atMs === undefined) return failure(`\`at\` must be a real local time formatted "YYYY-MM-DD HH:MM", got "${at}".`);
        if (atMs < now + MIN_LEAD_MS) return failure(`\`at\` (${at}) must be at least 1 minute in the future; it is now ${formatLocalDateTime(now)}.`);
        if (atMs > horizonEnd) return failure(`\`at\` (${at}) is beyond the ${config.maxHorizonDays}-day horizon.`);
        kind = 'once';
        spec = formatLocalDateTime(atMs);
        nextFireAtMs = atMs;
      } else {
        let cronSpec;
        try {
          cronSpec = parseCron(cron!);
        } catch (error) {
          if (error instanceof CronParseError) return failure(`Invalid cron expression: ${error.message}`);
          throw error;
        }
        const first = nextOccurrence(cronSpec, now);
        if (first === undefined) return failure(`Cron expression "${cronSpec.expression}" never fires.`);
        if (first > horizonEnd) return failure(`The first fire of "${cronSpec.expression}" (${formatLocalDateTime(first)}) is beyond the ${config.maxHorizonDays}-day horizon.`);
        const minGapLimit = config.minRecurringIntervalMin * 60_000;
        const gap = minGapMs(cronSpec, now, minGapLimit);
        if (gap !== undefined && gap < minGapLimit) {
          return failure(`"${cronSpec.expression}" can fire every ${Math.round(gap / 60_000)} minutes; recurring schedules must be at least ${config.minRecurringIntervalMin} minutes apart.`);
        }
        kind = 'cron';
        spec = cronSpec.expression;
        nextFireAtMs = first;
      }

      const taken = new Set(items.map(i => i.id));
      let id: string;
      do {
        id = randomUUID().slice(0, 8);
      } while (taken.has(id));

      const item: ScheduleItem = {
        id,
        kind,
        spec,
        note,
        ...(reason === undefined || reason === '' ? {} : { reason }),
        createdAtMs: now,
        nextFireAtMs,
      };
      store.save(chatId, [...items, item]);
      scheduler.rearm();
      return result({ id, kind, next_fire: formatLocalDateTime(nextFireAtMs), note });
    },
  };

  const listSchedules: PluginTool = {
    name: 'list_schedules',
    description: 'List your active scheduled wake-ups in this chat, with id, next fire time and note.',
    parameters: { type: 'object', properties: {} },
    execute: () => result({ schedules: store.list(chatId).map(describeItem) }),
  };

  const cancelSchedule: PluginTool = {
    name: 'cancel_schedule',
    description: 'Cancel one of your scheduled wake-ups in this chat by id (see list_schedules).',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Schedule id.' } },
      required: ['id'],
    },
    execute: input => {
      const parsed = v.safeParse(CancelInputSchema, input);
      if (!parsed.success) return failure('`id` is required.');
      const items = store.list(chatId);
      const target = items.find(i => i.id === parsed.output.id.trim());
      if (!target) return failure(`No schedule with id "${parsed.output.id}" in this chat. Use list_schedules to see the active ones.`);
      store.save(chatId, items.filter(i => i.id !== target.id));
      scheduler.rearm();
      return result({ cancelled: describeItem(target) });
    },
  };

  return [scheduleWakeup, listSchedules, cancelSchedule];
};
