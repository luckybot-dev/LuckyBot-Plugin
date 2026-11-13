import * as v from 'valibot';
import { afterEach, describe, expect, it } from 'vitest';

import { plugins } from '../index';
import type { PluginCapabilities } from '../sdk';
import { REDACT_PROMPT_HINT, RedactConfigSchema, redactPlugin, type RedactMode } from './index';

const SECRET = 'ghp_Ab3dE5gH7jK9mN1pQ3sT5vX7zB2cD4fG6hJ8';
const TEXT = `use ${SECRET} please, password=hunter2pass99`;

const start = async (mode: RedactMode): Promise<void> => {
  await redactPlugin.setup({
    config: v.parse(RedactConfigSchema, { mode }),
    capabilities: {} as PluginCapabilities,
    isEnabledForChat: () => true,
  });
};

const redactText = (text: string): string => redactPlugin.contributes!.redactText!(text);
const inspectText = (text: string) => redactPlugin.contributes!.inspectText!(text);
const hints = () => redactPlugin.contributes!.promptHints!('any-chat') ?? [];

afterEach(async () => {
  await redactPlugin.stop?.();
});

describe('config', () => {
  it('defaults to off', () => {
    expect(v.parse(RedactConfigSchema, {})).toEqual({ mode: 'off' });
  });

  it('accepts the three modes and nothing else', () => {
    for (const mode of ['off', 'shadow', 'enforce']) {
      expect(v.safeParse(RedactConfigSchema, { mode }).success).toBe(true);
    }
    expect(v.safeParse(RedactConfigSchema, { mode: 'on' }).success).toBe(false);
  });

  it('rejects the former `enabled` switch instead of ignoring it', () => {
    expect(v.safeParse(RedactConfigSchema, { enabled: true }).success).toBe(false);
  });
});

describe('registration', () => {
  it('is in the static plugin registry', () => {
    expect(plugins).toContain(redactPlugin);
    expect(redactPlugin.id).toBe('redact');
  });
});

describe('modes', () => {
  it('does nothing before setup and in mode off', async () => {
    expect(redactText(TEXT)).toBe(TEXT);
    expect(inspectText(TEXT)).toEqual([]);
    expect(hints()).toEqual([]);
    await start('off');
    expect(redactText(TEXT)).toBe(TEXT);
    expect(inspectText(TEXT)).toEqual([]);
    expect(hints()).toEqual([]);
  });

  it('enforce redacts and tells the model about the markers', async () => {
    await start('enforce');
    expect(redactText(TEXT)).toBe('use [redacted:api-key] please, password=[redacted:secret]');
    expect(inspectText(TEXT)).toEqual([]);
    expect(hints()).toEqual([{ placement: 'system', text: REDACT_PROMPT_HINT }]);
    expect(REDACT_PROMPT_HINT).toContain('[redacted:<kind>]');
    expect(REDACT_PROMPT_HINT).toMatch(/Do not ask anyone to post it again/);
  });

  it('shadow leaves the text alone, describes the hits and adds no hint', async () => {
    await start('shadow');
    expect(redactText(TEXT)).toBe(TEXT);
    const hits = inspectText(TEXT);
    expect(hits.map(h => h.kind)).toEqual(['api-key', 'secret']);
    expect(hits[0]).toMatchObject({ length: SECRET.length });
    expect(hits[0]!.hash).toMatch(/^[0-9a-f]{8}$/);
    expect(JSON.stringify(hits)).not.toContain('hunter2');
    expect(hints()).toEqual([]);
  });

  it('stop() switches it off again', async () => {
    await start('enforce');
    await redactPlugin.stop?.();
    expect(redactText(TEXT)).toBe(TEXT);
    expect(hints()).toEqual([]);
  });

  it('is deterministic', async () => {
    await start('enforce');
    expect(redactText(TEXT)).toBe(redactText(TEXT));
  });
});
