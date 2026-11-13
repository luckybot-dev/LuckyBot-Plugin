import * as v from 'valibot';

export const CronConfigSchema = v.object({
  maxActivePerChat: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1)), 20),
  maxHorizonDays: v.optional(v.pipe(v.number(), v.minValue(1)), 60),
  minRecurringIntervalMin: v.optional(v.pipe(v.number(), v.minValue(1)), 60),
  lateGraceHours: v.optional(v.pipe(v.number(), v.minValue(0)), 6),
});

export type CronPluginConfig = v.InferOutput<typeof CronConfigSchema>;

export const MAX_NOTE_CHARS = 300;
export const MAX_REASON_CHARS = 200;
/** One-shots must lie at least this far ahead. */
export const MIN_LEAD_MS = 60_000;

export const ScheduleItemSchema = v.object({
  id: v.string(),
  kind: v.picklist(['once', 'cron']),
  /** `YYYY-MM-DD HH:MM` for once, the 5-field expression for cron. */
  spec: v.string(),
  note: v.string(),
  reason: v.optional(v.string()),
  createdAtMs: v.number(),
  nextFireAtMs: v.number(),
  lastFiredAtMs: v.optional(v.number()),
});

export type ScheduleItem = v.InferOutput<typeof ScheduleItemSchema>;

export const ScheduleFileSchema = v.object({
  version: v.literal(1),
  items: v.array(ScheduleItemSchema),
});
