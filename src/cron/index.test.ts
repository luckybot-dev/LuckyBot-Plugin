import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import * as v from 'valibot';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { plugins } from '../index';
import { CRON_PROMPT_HINT, createCronPlugin, cronPlugin } from './index';
import { makeCapabilities, makeTmpDir, NOW } from './test-utils';
import { CronConfigSchema } from './types';

const config = v.parse(CronConfigSchema, {});

const toolsOf = (plugin: ReturnType<typeof createCronPlugin>, chatId: string) => {
  const fn = plugin.contributes?.tools;
  if (typeof fn !== 'function') throw new Error('tools must be a function');
  return fn(chatId, { enabled: true }) ?? [];
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe('config schema', () => {
  it('fills the documented defaults and validates ranges', () => {
    expect(config).toEqual({ maxActivePerChat: 20, maxHorizonDays: 60, minRecurringIntervalMin: 60, lateGraceHours: 6 });
    expect(v.safeParse(CronConfigSchema, { maxActivePerChat: 0 }).success).toBe(false);
    expect(v.safeParse(CronConfigSchema, { minRecurringIntervalMin: 'hourly' }).success).toBe(false);
    expect(v.parse(CronConfigSchema, { enabled: true, maxHorizonDays: 7 }).maxHorizonDays).toBe(7);
  });
});

describe('registration', () => {
  it('is in the static plugin registry', () => {
    expect(plugins).toContain(cronPlugin);
    expect(cronPlugin.id).toBe('cron');
  });
});

describe('prompt hint', () => {
  const hints = cronPlugin.contributes?.promptHints?.('any-chat') ?? [];

  it('is one system hint', () => {
    expect(hints).toEqual([{ placement: 'system', text: CRON_PROMPT_HINT }]);
  });

  it('frames requests as suggestions the bot may decline, with maintainers weighing a little more', () => {
    expect(CRON_PROMPT_HINT).toMatch(/your own decision/);
    expect(CRON_PROMPT_HINT).toMatch(/ask or suggest/);
    expect(CRON_PROMPT_HINT).toMatch(/right to decline/);
    expect(CRON_PROMPT_HINT).toMatch(/maintainer="true"\` somewhat more/);
  });

  it('never tells the bot to ignore people', () => {
    expect(CRON_PROMPT_HINT).not.toMatch(/ignore|disregard|don'?t listen|do not listen|never listen/i);
  });

  it('names the tools and the plugin-event line the probe/primary will see', () => {
    for (const name of ['schedule_wakeup', 'list_schedules', 'cancel_schedule']) expect(CRON_PROMPT_HINT).toContain(name);
    expect(CRON_PROMPT_HINT).toContain('<plugin-event plugin="cron">');
  });
});

describe('lifecycle', () => {
  it('contributes no tools before setup (the host probes tool names first) and for invalid chat ids', async () => {
    const plugin = createCronPlugin();
    expect(toolsOf(plugin, 'oc_a')).toEqual([]);

    const { capabilities } = makeCapabilities(makeTmpDir());
    await plugin.setup({ config, capabilities });
    expect(toolsOf(plugin, 'oc_a').map(t => t.name)).toEqual(['schedule_wakeup', 'list_schedules', 'cancel_schedule']);
    expect(toolsOf(plugin, '../etc')).toEqual([]);

    await plugin.stop?.();
    expect(toolsOf(plugin, 'oc_a')).toEqual([]);
  });

  it('schedules through the tool and wakes the chat when it fires', async () => {
    const plugin = createCronPlugin();
    const { capabilities, publish } = makeCapabilities(makeTmpDir());
    await plugin.setup({ config, capabilities });

    const tool = toolsOf(plugin, 'oc_a').find(t => t.name === 'schedule_wakeup')!;
    const out = JSON.parse((await tool.execute({ at: '2026-11-13 10:30', note: 'ask how the interview went' })).content);
    expect(out.next_fire).toBe('2026-11-13 10:30');

    await vi.advanceTimersByTimeAsync(31 * 60_000);
    expect(publish).toHaveBeenCalledOnce();
    const [chatId, options] = publish.mock.calls[0] as unknown as [string, { kind: string; text: string; wake: boolean }];
    expect(chatId).toBe('oc_a');
    expect(options).toMatchObject({ kind: 'cron', wake: true });
    expect(options.text).toContain('ask how the interview went');
    await plugin.stop?.();
  });

  it('does not fire for chats where the plugin is disabled, and keeps their items', async () => {
    const dir = makeTmpDir();
    const first = createCronPlugin();
    const a = makeCapabilities(dir, { isEnabledForChat: () => true });
    await first.setup({ config, capabilities: a.capabilities });
    await toolsOf(first, 'oc_a').find(t => t.name === 'schedule_wakeup')!.execute({ at: '2026-11-13 10:30', note: 'x' });
    await first.stop?.();

    const second = createCronPlugin();
    const b = makeCapabilities(dir, { isEnabledForChat: () => false });
    await second.setup({ config, capabilities: b.capabilities });
    await vi.advanceTimersByTimeAsync(2 * 3_600_000);
    expect(b.publish).not.toHaveBeenCalled();
    expect(JSON.parse(readFileSync(join(dir, 'oc_a.json'), 'utf8')).items).toHaveLength(1);
    await second.stop?.();
  });

  it('survives a restart: reloads items and keeps them armed', async () => {
    const dir = makeTmpDir();
    const first = createCronPlugin();
    await first.setup({ config, capabilities: makeCapabilities(dir).capabilities });
    await toolsOf(first, 'oc_a').find(t => t.name === 'schedule_wakeup')!.execute({ at: '2026-11-13 12:00', note: 'lunch' });
    await first.stop?.();

    const second = createCronPlugin();
    const b = makeCapabilities(dir);
    await second.setup({ config, capabilities: b.capabilities });
    expect(JSON.parse((await toolsOf(second, 'oc_a').find(t => t.name === 'list_schedules')!.execute({})).content).schedules).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2 * 3_600_000 + 1000);
    expect(b.publish).toHaveBeenCalledOnce();
    await second.stop?.();
  });

  it('logs an unreadable schedule file, leaves it untouched, and fails only that chat’s tools', async () => {
    const dir = makeTmpDir();
    writeFileSync(join(dir, 'oc_bad.json'), '{broken');
    const plugin = createCronPlugin();
    const { capabilities, log } = makeCapabilities(dir);
    await plugin.setup({ config, capabilities });

    expect(log.errors).toHaveLength(1);
    const list = toolsOf(plugin, 'oc_bad').find(t => t.name === 'list_schedules')!;
    expect(() => list.execute({})).toThrow();
    const ok = toolsOf(plugin, 'oc_good').find(t => t.name === 'list_schedules')!;
    expect(JSON.parse((await ok.execute({})).content)).toEqual({ schedules: [] });
    expect(readFileSync(join(dir, 'oc_bad.json'), 'utf8')).toBe('{broken');
    await plugin.stop?.();
  });
});
