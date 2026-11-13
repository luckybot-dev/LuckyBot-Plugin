import { Cron } from 'croner';

// Thin wrapper over `croner`, used only to evaluate expressions (no callback is
// ever attached, so no timer exists). Local time zone; `legacyMode` gives Vixie
// semantics for day-of-month / day-of-week (OR when both are restricted). One
// known difference: croner treats only a bare `*` as unrestricted, so `*/2` in
// day-of-month still ORs with day-of-week, where Vixie ANDs.
// Exactly 5 fields are accepted: the 6-field seconds form and `@daily` macros
// would bypass the minute granularity the interval limit reasons about.

export class CronParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CronParseError';
  }
}

export interface CronSpec {
  expression: string;
  cron: Cron;
}

export const parseCron = (expression: string): CronSpec => {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new CronParseError(`expected 5 fields (minute hour day-of-month month day-of-week), got ${fields.length}`);
  }
  const normalized = fields.join(' ');
  try {
    return { expression: normalized, cron: new Cron(normalized, { legacyMode: true }) };
  } catch (error) {
    throw new CronParseError(error instanceof Error ? error.message : String(error));
  }
};

/** First occurrence strictly after `afterMs`, or undefined if there is none. */
export const nextOccurrence = (spec: CronSpec, afterMs: number): number | undefined =>
  spec.cron.nextRun(new Date(afterMs))?.getTime();

export interface MinGapOptions {
  horizonDays?: number;
  maxOccurrences?: number;
}

/**
 * Smallest gap between consecutive occurrences after `fromMs`, scanned over a
 * horizon (default one year, so month/day restricted expressions show their
 * tightest pair) and capped at `maxOccurrences`. Returns undefined with fewer
 * than two occurrences in the horizon. Stops early once `stopBelowMs` is
 * undercut, which is all the limit check needs.
 */
export const minGapMs = (
  spec: CronSpec,
  fromMs: number,
  stopBelowMs: number,
  { horizonDays = 366, maxOccurrences = 20_000 }: MinGapOptions = {},
): number | undefined => {
  const end = fromMs + horizonDays * 86_400_000;
  let prev = nextOccurrence(spec, fromMs);
  let min: number | undefined;
  for (let i = 0; prev !== undefined && i < maxOccurrences; i++) {
    const next = nextOccurrence(spec, prev);
    if (next === undefined || next > end) break;
    const gap = next - prev;
    if (min === undefined || gap < min) min = gap;
    if (min < stopBelowMs) return min;
    prev = next;
  }
  return min;
};
