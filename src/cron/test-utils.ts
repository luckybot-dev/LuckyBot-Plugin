import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, vi } from 'vitest';

import type { PluginCapabilities, PluginLogger } from '../sdk';
import type { CronPluginConfig, ScheduleItem } from './types';

export const DEFAULT_CONFIG: CronPluginConfig = {
  maxActivePerChat: 20,
  maxHorizonDays: 60,
  minRecurringIntervalMin: 60,
  lateGraceHours: 6,
};

/** Local wall-clock time as epoch ms, independent of the test machine's zone. */
export const local = (y: number, mo: number, d: number, h = 0, min = 0): number =>
  new Date(y, mo - 1, d, h, min, 0, 0).getTime();

export const NOW = local(2026, 11, 13, 10, 0);

const tmpDirs: string[] = [];
export const makeTmpDir = (): string => {
  const dir = mkdtempSync(join(tmpdir(), 'cron-plugin-'));
  tmpDirs.push(dir);
  return dir;
};
afterEach(() => {
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

export const makeLogger = (): PluginLogger & { errors: unknown[][] } => {
  const errors: unknown[][] = [];
  const logger: PluginLogger & { errors: unknown[][] } = {
    errors,
    log: vi.fn(),
    warn: vi.fn(),
    error: (...args: unknown[]) => { errors.push(args); },
    debug: vi.fn(),
    withFields: () => logger,
    withError: () => logger,
  };
  return logger;
};

export const makeItem = (overrides: Partial<ScheduleItem> = {}): ScheduleItem => ({
  id: 'item0001',
  kind: 'once',
  spec: '2026-11-13 12:00',
  note: 'check the oven',
  createdAtMs: NOW - 3_600_000,
  nextFireAtMs: local(2026, 11, 13, 12, 0),
  ...overrides,
});

export const makeCapabilities = (
  rootDir: string,
  overrides: { publish?: PluginCapabilities['chat']['publish']; isEnabledForChat?: (chatId: string) => boolean } = {},
) => {
  const publish = vi.fn(overrides.publish ?? (() => {}));
  const log = makeLogger();
  const capabilities = {
    callModel: () => Promise.resolve(''),
    ask: () => Promise.resolve({ choice: '' }),
    isEnabledForChat: overrides.isEnabledForChat ?? (() => true),
    http: { route: vi.fn() },
    chat: { publish },
    scene: { enter: vi.fn(), exit: vi.fn(), note: vi.fn() },
    storage: { rootDir },
    log,
    media: { send: () => Promise.resolve() },
  } as PluginCapabilities;
  return { capabilities, publish, log };
};
