import { cronPlugin } from './cron';
import { tavernPlugin } from './tavern';
import { webPlugin } from './web';

export * from './sdk';
export * from './cron';
export * from './tavern';
export * from './web';
export { liarsBarModule } from './games/liars-bar';

export const plugins = [
  cronPlugin,
  tavernPlugin,
  webPlugin,
] as const;
