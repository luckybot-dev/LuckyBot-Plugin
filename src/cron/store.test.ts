import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createScheduleStore, isValidChatId } from './store';
import { makeItem, makeTmpDir } from './test-utils';

describe('isValidChatId', () => {
  it('accepts platform ids and rejects anything path-like', () => {
    for (const ok of ['oc_abc123', '-1001234567', 'default', 'a'.repeat(64)]) expect(isValidChatId(ok)).toBe(true);
    for (const bad of ['', '..', '../x', 'a/b', 'a.b', 'a b', 'a'.repeat(65), 'x\0y']) expect(isValidChatId(bad)).toBe(false);
  });
});

describe('createScheduleStore', () => {
  it('round-trips items through a file per chat, atomically', () => {
    const dir = makeTmpDir();
    const store = createScheduleStore(dir);
    const item = makeItem({ reason: 'Alice asked', lastFiredAtMs: 5 });
    store.save('oc_one', [item]);

    expect(readdirSync(dir)).toEqual(['oc_one.json']); // tmp file renamed away
    expect(JSON.parse(readFileSync(join(dir, 'oc_one.json'), 'utf8'))).toEqual({ version: 1, items: [item] });

    const reopened = createScheduleStore(dir);
    expect(reopened.list('oc_one')).toEqual([item]);
    expect(reopened.list('oc_other')).toEqual([]);
  });

  it('creates the root directory on first save', () => {
    const dir = join(makeTmpDir(), 'nested', 'cron');
    createScheduleStore(dir).save('c1', [makeItem()]);
    expect(existsSync(join(dir, 'c1.json'))).toBe(true);
  });

  it('returns copies so callers cannot mutate the cache', () => {
    const store = createScheduleStore(makeTmpDir());
    store.save('c1', [makeItem()]);
    store.list('c1')[0]!.note = 'changed';
    expect(store.list('c1')[0]!.note).toBe('check the oven');
  });

  it('rejects an invalid chatId before touching the filesystem', () => {
    const dir = makeTmpDir();
    const store = createScheduleStore(dir);
    expect(() => store.list('../evil')).toThrow(/Invalid chatId/);
    expect(() => store.save('a/b', [])).toThrow(/Invalid chatId/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('loadAll loads good files and reports bad ones without touching them', () => {
    const dir = makeTmpDir();
    createScheduleStore(dir).save('good', [makeItem()]);
    writeFileSync(join(dir, 'corrupt.json'), '{not json');
    writeFileSync(join(dir, 'wrongshape.json'), JSON.stringify({ version: 1, items: [{ id: 1 }] }));
    writeFileSync(join(dir, 'bad name.json'), '{}');
    writeFileSync(join(dir, 'good.json.tmp'), 'leftover');

    const store = createScheduleStore(dir);
    const { failed, skippedNames } = store.loadAll();
    expect(store.chatIds()).toEqual(['good']);
    expect(failed.map(f => f.chatId).sort()).toEqual(['corrupt', 'wrongshape']);
    expect(skippedNames).toEqual(['bad name.json']);
    expect(readFileSync(join(dir, 'corrupt.json'), 'utf8')).toBe('{not json');
    expect(() => store.list('corrupt')).toThrow();
  });

  it('loadAll tolerates a missing root directory', () => {
    const store = createScheduleStore(join(makeTmpDir(), 'missing'));
    expect(store.loadAll()).toEqual({ failed: [], skippedNames: [] });
  });
});
