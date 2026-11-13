import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PluginTool } from '../sdk';
import type { Scheduler } from './scheduler';
import { createScheduleStore } from './store';
import { DEFAULT_CONFIG, local, makeItem, makeTmpDir, NOW } from './test-utils';
import { createCronTools } from './tools';
import type { CronPluginConfig } from './types';

const setup = (config: CronPluginConfig = DEFAULT_CONFIG) => {
  const store = createScheduleStore(makeTmpDir());
  const scheduler: Scheduler = { start: vi.fn(), rearm: vi.fn(), stop: vi.fn() };
  const tools = createCronTools({ chatId: 'oc_a', store, scheduler, config });
  const byName = (name: string): PluginTool => tools.find(t => t.name === name)!;
  const call = async (name: string, input: unknown) => {
    const res = await byName(name).execute(input);
    return JSON.parse(res.content) as Record<string, unknown>;
  };
  return { store, scheduler, tools, call };
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe('schedule_wakeup', () => {
  it('creates a one-shot, persists it and re-arms the timer', async () => {
    const { call, store, scheduler } = setup();
    const out = await call('schedule_wakeup', { at: '2026-11-14 08:00', note: '提醒她带伞', reason: 'Alice asked' });
    expect(out).toMatchObject({ kind: 'once', next_fire: '2026-11-14 08:00', note: '提醒她带伞' });
    const [item] = store.list('oc_a');
    expect(item).toMatchObject({
      id: out.id,
      kind: 'once',
      spec: '2026-11-14 08:00',
      reason: 'Alice asked',
      createdAtMs: NOW,
      nextFireAtMs: local(2026, 11, 14, 8, 0),
    });
    expect(scheduler.rearm).toHaveBeenCalledOnce();
  });

  it('creates a recurring schedule with its resolved next fire time', async () => {
    const { call, store } = setup();
    const out = await call('schedule_wakeup', { cron: '0 9 * * 1-5', note: 'morning check' });
    expect(out).toMatchObject({ kind: 'cron', next_fire: '2026-11-16 09:00' });
    expect(store.list('oc_a')[0]).toMatchObject({ kind: 'cron', spec: '0 9 * * 1-5', nextFireAtMs: local(2026, 11, 16, 9, 0) });
  });

  it('collapses whitespace in note and omits an empty reason', async () => {
    const { call, store } = setup();
    await call('schedule_wakeup', { at: '2026-11-14 08:00', note: '  a\n b\t c ', reason: '  ' });
    const [item] = store.list('oc_a');
    expect(item?.note).toBe('a b c');
    expect(item).not.toHaveProperty('reason');
  });

  it.each([
    ['neither at nor cron', { note: 'x' }, /exactly one/],
    ['both at and cron', { at: '2026-11-14 08:00', cron: '0 9 * * *', note: 'x' }, /exactly one/],
    ['empty note', { at: '2026-11-14 08:00', note: '   ' }, /must not be empty/],
    ['over-long note', { at: '2026-11-14 08:00', note: 'x'.repeat(301) }, /limit is 300/],
    ['over-long reason', { at: '2026-11-14 08:00', note: 'x', reason: 'r'.repeat(201) }, /reason/],
    ['missing note', { at: '2026-11-14 08:00' }, /Invalid input/],
    ['malformed at', { at: 'tomorrow 8am', note: 'x' }, /YYYY-MM-DD HH:MM/],
    ['impossible date', { at: '2026-02-30 08:00', note: 'x' }, /real local time/],
    ['past time', { at: '2026-11-13 09:00', note: 'x' }, /at least 1 minute/],
    ['30 seconds ahead', { at: '2026-11-13 10:00', note: 'x' }, /at least 1 minute/],
    ['beyond the horizon', { at: '2027-03-01 08:00', note: 'x' }, /60-day horizon/],
    ['bad cron', { cron: '61 * * * *', note: 'x' }, /Invalid cron expression/],
    ['six-field cron', { cron: '0 0 9 * * *', note: 'x' }, /expected 5 fields/],
    ['never-firing cron', { cron: '0 0 30 2 *', note: 'x' }, /never fires/],
    ['cron too frequent', { cron: '*/5 * * * *', note: 'x' }, /every 5 minutes.*at least 60/],
    ['cron with a close pair of times', { cron: '0,30 9 * * *', note: 'x' }, /every 30 minutes/],
    ['cron first fire past the horizon', { cron: '0 0 1 6 *', note: 'x' }, /beyond the 60-day horizon/],
  ])('returns a tool error for %s', async (_label, input, message) => {
    const { call, store, scheduler } = setup();
    const out = await call('schedule_wakeup', input);
    expect(out.error).toMatch(message);
    expect(store.list('oc_a')).toEqual([]);
    expect(scheduler.rearm).not.toHaveBeenCalled();
  });

  it('accepts a one-shot exactly one minute ahead and exactly at the horizon', async () => {
    const { call } = setup();
    expect(await call('schedule_wakeup', { at: '2026-11-13 10:01', note: 'x' })).toHaveProperty('id');
    expect(await call('schedule_wakeup', { at: '2027-01-12 10:00', note: 'x' })).toHaveProperty('id');
  });

  it('enforces maxActivePerChat', async () => {
    const { call, store } = setup({ ...DEFAULT_CONFIG, maxActivePerChat: 2 });
    store.save('oc_a', [makeItem({ id: 'a' }), makeItem({ id: 'b' })]);
    const out = await call('schedule_wakeup', { at: '2026-11-14 08:00', note: 'x' });
    expect(out.error).toMatch(/already has 2 active schedules/);
    expect(store.list('oc_a')).toHaveLength(2);
  });

  it('honours configured limits', async () => {
    const { call } = setup({ ...DEFAULT_CONFIG, minRecurringIntervalMin: 5, maxHorizonDays: 3 });
    expect(await call('schedule_wakeup', { cron: '*/5 * * * *', note: 'x' })).toHaveProperty('id');
    expect((await call('schedule_wakeup', { at: '2026-11-20 08:00', note: 'x' })).error).toMatch(/3-day horizon/);
  });

  it('states the limits in its description', () => {
    const { tools } = setup();
    const description = tools.find(t => t.name === 'schedule_wakeup')!.description;
    expect(description).toMatch(/at most 20 active/);
    expect(description).toMatch(/within 60 days/);
    expect(description).toMatch(/every 60 minutes/);
    expect(description).toMatch(/local time/);
  });

  it('requires a follow-up so the model sees the id and can confirm in chat', async () => {
    const { tools } = setup();
    const res = await tools.find(t => t.name === 'schedule_wakeup')!.execute({ at: '2026-11-14 08:00', note: 'x' });
    expect(res.requiresFollowUp).toBe(true);
  });
});

describe('list_schedules / cancel_schedule', () => {
  it('lists only this chat’s items', async () => {
    const { call, store } = setup();
    store.save('oc_a', [makeItem({ id: 'a1', kind: 'cron', spec: '0 9 * * *', lastFiredAtMs: local(2026, 11, 12, 9, 0) })]);
    store.save('oc_b', [makeItem({ id: 'b1' })]);
    expect(await call('list_schedules', {})).toEqual({
      schedules: [{
        id: 'a1',
        kind: 'cron',
        cron: '0 9 * * *',
        next_fire: '2026-11-13 12:00',
        note: 'check the oven',
        last_fired: '2026-11-12 09:00',
      }],
    });
  });

  it('cancels by id and re-arms', async () => {
    const { call, store, scheduler } = setup();
    store.save('oc_a', [makeItem({ id: 'a1' }), makeItem({ id: 'a2' })]);
    const out = await call('cancel_schedule', { id: 'a1' });
    expect(out).toMatchObject({ cancelled: { id: 'a1' } });
    expect(store.list('oc_a').map(i => i.id)).toEqual(['a2']);
    expect(scheduler.rearm).toHaveBeenCalledOnce();
  });

  it('cannot cancel another chat’s item, and reports unknown ids as an error result', async () => {
    const { call, store, scheduler } = setup();
    store.save('oc_b', [makeItem({ id: 'b1' })]);
    expect((await call('cancel_schedule', { id: 'b1' })).error).toMatch(/No schedule with id "b1"/);
    expect((await call('cancel_schedule', {})).error).toMatch(/id/);
    expect(store.list('oc_b')).toHaveLength(1);
    expect(scheduler.rearm).not.toHaveBeenCalled();
  });
});
