import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import * as v from 'valibot';

import { ScheduleFileSchema, type ScheduleItem } from './types';

// Same shape as the memory store's id guard: validated before any path is built.
const CHAT_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export const isValidChatId = (chatId: string): boolean => CHAT_ID_PATTERN.test(chatId);

export interface ScheduleStore {
  /** Items of one chat (a copy). Throws on an invalid chatId or an unreadable file. */
  list(chatId: string): ScheduleItem[];
  /** Atomically replaces a chat's items. */
  save(chatId: string, items: ScheduleItem[]): void;
  /** Chats whose items are loaded in memory. */
  chatIds(): string[];
  /** Loads every chat file; a bad file is reported, never overwritten. */
  loadAll(): { failed: { chatId: string; error: unknown }[]; skippedNames: string[] };
}

export const createScheduleStore = (rootDir: string): ScheduleStore => {
  const cache = new Map<string, ScheduleItem[]>();

  const assertChatId = (chatId: string): void => {
    if (!isValidChatId(chatId)) throw new Error(`Invalid chatId for schedule storage: ${JSON.stringify(chatId)}`);
  };

  const fileOf = (chatId: string): string => join(rootDir, `${chatId}.json`);

  const read = (chatId: string): ScheduleItem[] => {
    let text: string;
    try {
      text = readFileSync(fileOf(chatId), 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
    return v.parse(ScheduleFileSchema, JSON.parse(text)).items;
  };

  const list = (chatId: string): ScheduleItem[] => {
    assertChatId(chatId);
    let items = cache.get(chatId);
    if (!items) {
      items = read(chatId);
      cache.set(chatId, items);
    }
    return items.map(item => ({ ...item }));
  };

  const save = (chatId: string, items: ScheduleItem[]): void => {
    assertChatId(chatId);
    mkdirSync(rootDir, { recursive: true });
    const target = fileOf(chatId);
    const tmp = `${target}.tmp`;
    writeFileSync(tmp, `${JSON.stringify({ version: 1, items }, null, 2)}\n`, 'utf8');
    renameSync(tmp, target);
    cache.set(chatId, items.map(item => ({ ...item })));
  };

  const loadAll = () => {
    const failed: { chatId: string; error: unknown }[] = [];
    const skippedNames: string[] = [];
    let names: string[];
    try {
      names = readdirSync(rootDir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { failed, skippedNames };
      throw error;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const chatId = name.slice(0, -'.json'.length);
      if (!isValidChatId(chatId)) {
        skippedNames.push(name);
        continue;
      }
      try {
        cache.set(chatId, read(chatId));
      } catch (error) {
        failed.push({ chatId, error });
      }
    }
    return { failed, skippedNames };
  };

  return { list, save, chatIds: () => [...cache.keys()], loadAll };
};
