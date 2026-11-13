import { cronPlugin } from './cron';
import { redactPlugin } from './redact';
import { tavernPlugin } from './tavern';
import { webPlugin } from './web';

export * from './sdk';
export * from './cron';
export * from './redact';
export * from './tavern';
export * from './web';
export { liarsBarModule } from './games/liars-bar';

export const plugins = [
  cronPlugin,
  redactPlugin,
  tavernPlugin,
  webPlugin,
] as const;
