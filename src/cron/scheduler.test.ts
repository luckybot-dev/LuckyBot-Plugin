import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { buildFireText, createScheduler, STARTUP_DELAY_MS } from './scheduler';
import { createScheduleStore } from './store';
import { DEFAULT_CONFIG, local, makeItem, makeLogger, makeTmpDir, NOW } from './test-utils';
import type { CronPluginConfig } from './types';

const HOUR = 3_600_000;
const MIN = 60_000;

const setup = (opts: { enabled?: (chatId: string) => boolean; config?: CronPluginConfig; publish?: (chatId: string, options: { kind: string; text: string; wake: boolean }) => void } = {}) => {
  const store = createScheduleStore(makeTmpDir());
  const publish = vi.fn<NonNullable<typeof opts.publish>>(opts.publish ?? (() => {}));
  const log = makeLogger();
  const scheduler = createScheduler({
    store,
    config: opts.config ?? DEFAULT_CONFIG,
    isEnabled: opts.enabled ?? (() => true),
    publish,
    log,
  });
  return { store, publish, scheduler, log };
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe('firing', () => {
  it('fires a one-shot at its time with a wake-up event, then deletes it', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ nextFireAtMs: NOW + 30 * MIN, note: 'ask about the exam' })]);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(29 * MIN);
    expect(publish).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1 * MIN + 1000);

    expect(publish).toHaveBeenCalledOnce();
    const [chatId, options] = publish.mock.calls[0]!;
    expect(chatId).toBe('c1');
    expect(options).toMatchObject({ kind: 'cron', wake: true });
    expect(options.text).toContain('Your own scheduled wake-up fired');
    expect(options.text).toContain('ask about the exam');
    expect(options.text).not.toContain('late');
    expect(store.list('c1')).toEqual([]);
  });

  it('fires a recurring item and advances it to the next occurrence', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ kind: 'cron', spec: '0 12 * * *', nextFireAtMs: local(2026, 11, 13, 12, 0) })]);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(2 * HOUR + 1000);
    expect(publish).toHaveBeenCalledOnce();
    expect(publish.mock.calls[0]![1].text).toContain('recurring "0 12 * * *"');
    const [item] = store.list('c1');
    expect(item?.nextFireAtMs).toBe(local(2026, 11, 14, 12, 0));
    expect(item?.lastFiredAtMs).toBeGreaterThanOrEqual(local(2026, 11, 13, 12, 0));

    await vi.advanceTimersByTimeAsync(24 * HOUR);
    expect(publish).toHaveBeenCalledTimes(2);
  });

  it('reaches an item further out than a single timer can span', async () => {
    const { store, publish, scheduler } = setup();
    const thirtyDays = 30 * 24 * HOUR;
    store.save('c1', [makeItem({ nextFireAtMs: NOW + thirtyDays })]);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(thirtyDays - MIN);
    expect(publish).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2 * MIN);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('arms for an item added after start via rearm()', async () => {
    const { store, publish, scheduler } = setup();
    scheduler.start();
    store.save('c1', [makeItem({ nextFireAtMs: NOW + 10 * MIN })]);
    scheduler.rearm();
    await vi.advanceTimersByTimeAsync(11 * MIN);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('picks up an earlier item added while a later one is armed', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ id: 'late', nextFireAtMs: NOW + 5 * HOUR })]);
    scheduler.start();
    store.save('c1', [...store.list('c1'), makeItem({ id: 'early', nextFireAtMs: NOW + 10 * MIN })]);
    scheduler.rearm();
    await vi.advanceTimersByTimeAsync(11 * MIN);
    expect(publish).toHaveBeenCalledOnce();
    expect(store.list('c1').map(i => i.id)).toEqual(['late']);
  });

  it('stop() prevents further fires', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ nextFireAtMs: NOW + 10 * MIN })]);
    scheduler.start();
    scheduler.stop();
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(publish).not.toHaveBeenCalled();
    expect(store.list('c1')).toHaveLength(1);
  });

  it('keeps the item and retries after a pause when publishing fails', async () => {
    let failing = true;
    const { store, publish, scheduler, log } = setup({ publish: () => { if (failing) throw new Error('sink down'); } });
    store.save('c1', [makeItem({ nextFireAtMs: NOW + 10 * MIN })]);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(10 * MIN + 1000);
    expect(publish).toHaveBeenCalledTimes(1);
    expect(store.list('c1')).toHaveLength(1);
    expect(log.errors).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(30_000); // no spinning inside the pause
    expect(publish).toHaveBeenCalledTimes(1);

    failing = false;
    await vi.advanceTimersByTimeAsync(40_000);
    expect(publish).toHaveBeenCalledTimes(2);
    expect(store.list('c1')).toEqual([]);
  });
});

describe('disabled chats', () => {
  it('neither fires nor drops items of a disabled chat, but still serves enabled ones', async () => {
    const { store, publish, scheduler } = setup({ enabled: chatId => chatId === 'on' });
    store.save('off', [makeItem({ id: 'o', nextFireAtMs: NOW + 10 * MIN })]);
    store.save('on', [makeItem({ id: 'n', nextFireAtMs: NOW + 20 * MIN })]);
    scheduler.start();

    await vi.advanceTimersByTimeAsync(HOUR);
    expect(publish.mock.calls.map(c => c[0])).toEqual(['on']);
    expect(store.list('off').map(i => i.id)).toEqual(['o']);
    expect(store.list('on')).toEqual([]);
  });
});

describe('startup catch-up', () => {
  it('waits for the startup delay before publishing', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ nextFireAtMs: NOW - 10 * MIN })]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(STARTUP_DELAY_MS - 100);
    expect(publish).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(200);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('fires an overdue one-shot once, with how late it is', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ nextFireAtMs: NOW - 2 * HOUR - 15 * MIN })]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(STARTUP_DELAY_MS + 100);
    await vi.advanceTimersByTimeAsync(HOUR);

    expect(publish).toHaveBeenCalledOnce();
    expect(publish.mock.calls[0]![1].text).toContain('(2 h 15 min late)');
    expect(store.list('c1')).toEqual([]);
  });

  it('drops a one-shot overdue beyond lateGraceHours without firing', async () => {
    const { store, publish, scheduler, log } = setup();
    store.save('c1', [
      makeItem({ id: 'stale', nextFireAtMs: NOW - 6 * HOUR - MIN }),
      makeItem({ id: 'fresh', nextFireAtMs: NOW - 5 * HOUR }),
    ]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(STARTUP_DELAY_MS + 100);

    expect(publish).toHaveBeenCalledOnce();
    expect(store.list('c1')).toEqual([]);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('overdue beyond lateGraceHours'));
  });

  it('skips missed occurrences of a recurring item: no burst, moves to the next future one', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({
      kind: 'cron',
      spec: '0 * * * *',
      nextFireAtMs: NOW - 5 * HOUR, // five missed hourly occurrences
    })]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(STARTUP_DELAY_MS + 100);

    expect(publish).not.toHaveBeenCalled();
    const [item] = store.list('c1');
    expect(item?.nextFireAtMs).toBe(local(2026, 11, 13, 11, 0));
    expect(item?.lastFiredAtMs).toBeUndefined();

    await vi.advanceTimersByTimeAsync(HOUR);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('still fires a recurring occurrence that is only slightly late', async () => {
    const { store, publish, scheduler } = setup();
    store.save('c1', [makeItem({ kind: 'cron', spec: '0 * * * *', nextFireAtMs: NOW - MIN })]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(STARTUP_DELAY_MS + 100);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('leaves everything in a disabled chat alone, even stale one-shots', async () => {
    const { store, publish, scheduler } = setup({ enabled: () => false });
    store.save('c1', [makeItem({ nextFireAtMs: NOW - 48 * HOUR })]);
    scheduler.start();
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(publish).not.toHaveBeenCalled();
    expect(store.list('c1')).toHaveLength(1);
  });
});

describe('buildFireText', () => {
  it('names the note, marks it as the bot’s own decision and reports lateness only when notable', () => {
    const item = makeItem({ note: 'water the plants' });
    const onTime = buildFireText(item, 5_000);
    expect(onTime).toContain('Your own scheduled wake-up fired.');
    expect(onTime).toContain('"water the plants"');
    expect(onTime).toMatch(/your own decision/);
    expect(onTime).toMatch(/reason to act unless the moment has clearly passed/);
    expect(buildFireText(item, 45 * MIN)).toContain('fired (45 min late).');
  });
});
