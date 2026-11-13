import { describe, expect, it } from 'vitest';

import { CronParseError, minGapMs, nextOccurrence, parseCron } from './parser';
import { local } from './test-utils';

const next = (expr: string, after: number) => nextOccurrence(parseCron(expr), after);

describe('parseCron', () => {
  it('accepts exactly five fields', () => {
    expect(parseCron('  0   9 * *  1-5 ').expression).toBe('0 9 * * 1-5');
    expect(() => parseCron('0 9 * *')).toThrow(CronParseError);
    expect(() => parseCron('0 0 9 * * *')).toThrow(/expected 5 fields/);
  });

  it('rejects macros, bad values and numeric-prefix steps', () => {
    expect(() => parseCron('@daily')).toThrow(CronParseError);
    expect(() => parseCron('61 * * * *')).toThrow(CronParseError);
    expect(() => parseCron('* 24 * * *')).toThrow(CronParseError);
    expect(() => parseCron('* * 0 * *')).toThrow(CronParseError);
    expect(() => parseCron('* * * 13 *')).toThrow(CronParseError);
    expect(() => parseCron('5/15 * * * *')).toThrow(CronParseError);
    expect(() => parseCron('a * * * *')).toThrow(CronParseError);
  });
});

describe('nextOccurrence', () => {
  const base = local(2026, 11, 13, 10, 0);

  it('finds the next daily time, strictly after the reference', () => {
    expect(next('0 9 * * *', base)).toBe(local(2026, 11, 14, 9, 0));
    expect(next('0 10 * * *', base)).toBe(local(2026, 11, 14, 10, 0));
    expect(next('30 10 * * *', base)).toBe(local(2026, 11, 13, 10, 30));
  });

  it('handles steps, lists and ranges', () => {
    expect(next('*/15 * * * *', base)).toBe(local(2026, 11, 13, 10, 15));
    expect(next('10-20/5 11 * * *', base)).toBe(local(2026, 11, 13, 11, 10));
    expect(next('0,30 14,16 * * *', base)).toBe(local(2026, 11, 13, 14, 0));
  });

  it('treats 0 and 7 as Sunday', () => {
    const sunday = local(2026, 11, 15, 9, 0);
    expect(next('0 9 * * 0', base)).toBe(sunday);
    expect(next('0 9 * * 7', base)).toBe(sunday);
  });

  it('uses OR when both day-of-month and day-of-week are restricted (Vixie)', () => {
    // 2026-11-13 is a Friday. "the 15th or any Monday": the Monday (16th) is after the 15th.
    expect(next('0 9 15 * 1', base)).toBe(local(2026, 11, 15, 9, 0));
    // "the 20th or any Friday" next Friday is the 20th too; use the 18th: Friday 20th beats nothing, 18th comes first.
    expect(next('0 9 18 * 5', base)).toBe(local(2026, 11, 18, 9, 0));
    expect(next('0 9 25 * 5', base)).toBe(local(2026, 11, 20, 9, 0));
  });

  it('uses AND when one of the day fields is a wildcard', () => {
    expect(next('0 9 13 * *', base)).toBe(local(2026, 12, 13, 9, 0));
    expect(next('0 9 * * 5', base)).toBe(local(2026, 11, 20, 9, 0));
  });

  it('rolls over months and years', () => {
    expect(next('0 0 1 1 *', base)).toBe(local(2027, 1, 1, 0, 0));
    expect(next('59 23 31 12 *', base)).toBe(local(2026, 12, 31, 23, 59));
  });

  it('skips impossible dates and finds leap days', () => {
    expect(next('0 0 30 2 *', base)).toBeUndefined();
    expect(next('0 0 29 2 *', base)).toBe(local(2028, 2, 29, 0, 0));
  });
});

describe('minGapMs', () => {
  const from = local(2026, 11, 13, 10, 0);
  const minute = 60_000;

  it('reports the tightest gap', () => {
    expect(minGapMs(parseCron('*/5 * * * *'), from, 60 * minute)).toBe(5 * minute);
    expect(minGapMs(parseCron('0 * * * *'), from, 30 * minute)).toBe(60 * minute);
    expect(minGapMs(parseCron('0 9 * * *'), from, 30 * minute)).toBe(24 * 60 * minute);
  });

  it('sees gaps that only appear across midnight', () => {
    expect(minGapMs(parseCron('0,59 0,23 * * *'), from, 1)).toBe(minute);
  });

  it('sees gaps that only appear across months', () => {
    // Dec 31 23:59 -> Jan 1 00:00 is one minute apart.
    expect(minGapMs(parseCron('59,0 23,0 31,1 12,1 *'), from, 1)).toBe(minute);
  });

  it('stops at the first gap below the limit', () => {
    expect(minGapMs(parseCron('0,59 0,23 * * *'), from, 60 * minute)).toBe(59 * minute);
  });

  it('is undefined with fewer than two occurrences in the horizon', () => {
    expect(minGapMs(parseCron('0 0 30 2 *'), from, 60 * minute)).toBeUndefined();
    expect(minGapMs(parseCron('0 0 1 1 *'), from, 60 * minute)).toBeUndefined();
  });
});
