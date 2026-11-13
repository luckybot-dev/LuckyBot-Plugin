import { describeSecrets, redactSecrets } from './rules';
import { RedactConfigSchema, type RedactMode, type RedactPluginConfig } from './types';
import { CURRENT_SDK_VERSION, definePlugin } from '../sdk';

export { RedactConfigSchema, REDACT_MODES, type RedactMode, type RedactPluginConfig } from './types';
export { describeSecrets, findSecrets, redactSecrets, type RedactHit, type RedactKind, type RedactSpan } from './rules';

export const REDACT_PROMPT_HINT = [
  'Credentials and secret material in this conversation (API keys, tokens, passwords, private keys, seed phrases, bank card and ID numbers)',
  'are removed before they reach you and show up as `[redacted:<kind>]`. You cannot recover the original value.',
  'Do not ask anyone to post it again, and do not try to guess or reconstruct it; work with the marker as it is.',
].join(' ');

// The host reads `contributes` once, before `setup` runs, so the mode lives in
// module state (like the other plugins' global config) and the functions read it
// per call. Until `setup` has run, and after `stop`, the plugin does nothing.
let mode: RedactMode = 'off';

export const redactPlugin = definePlugin<RedactPluginConfig>({
  id: 'redact',
  sdkVersion: CURRENT_SDK_VERSION,
  configSchema: RedactConfigSchema,
  contributes: {
    redactText: (text: string): string => (mode === 'enforce' ? redactSecrets(text) : text),
    inspectText: (text: string) => (mode === 'shadow' ? describeSecrets(text) : []),
    // Shadow keeps the model's view untouched, so it gets no hint either.
    promptHints: () => (mode === 'enforce' ? [{ placement: 'system', text: REDACT_PROMPT_HINT }] : undefined),
  },
  setup(ctx) {
    mode = ctx.config.mode;
  },
  stop() {
    mode = 'off';
  },
});
