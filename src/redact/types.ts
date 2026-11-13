import * as v from 'valibot';

export const REDACT_MODES = ['off', 'shadow', 'enforce'] as const;
export type RedactMode = (typeof REDACT_MODES)[number];

// strictObject: the former `enabled` switch must fail loudly, not be ignored.
export const RedactConfigSchema = v.strictObject({
  mode: v.optional(v.picklist(REDACT_MODES), 'off'),
});

export type RedactPluginConfig = v.InferOutput<typeof RedactConfigSchema>;
