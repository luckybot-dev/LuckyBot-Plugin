import { CURRENT_SDK_VERSION, definePlugin, type PluginDefinition } from '../sdk';
import { createScheduler, type Scheduler } from './scheduler';
import { createScheduleStore, isValidChatId, type ScheduleStore } from './store';
import { createCronTools } from './tools';
import { CronConfigSchema, type CronPluginConfig } from './types';

export { CronConfigSchema, type CronPluginConfig } from './types';

// Only `system` hints reach the primary prompt; the probe prompt gets none, so
// the fired event text (see buildFireText) carries the probe-facing wording.
export const CRON_PROMPT_HINT = '**Scheduled wake-ups:** You can set your own future wake-ups with `schedule_wakeup` (a one-off local time or a cron expression), review them with `list_schedules` and drop them with `cancel_schedule`. What you schedule is your own decision. People may ask or suggest something ("remind me at 8 tomorrow"); you can take that into account, a message marked `maintainer="true"` somewhat more than others, and you have the right to decline, in character. Write each `note` as a short line to your future self; it lands in the chat context where everyone can read it, so keep anything private out of it. Schedule sparingly: a few useful ones, not a stream. When a `<plugin-event plugin="cron">` line shows a schedule firing, it is your own earlier decision waking you: a reason to act unless the moment has clearly passed, though you may still stay silent.';

interface CronState {
  store: ScheduleStore;
  scheduler: Scheduler;
  config: CronPluginConfig;
}

/** A factory so each instance (and each test) owns its state. */
export const createCronPlugin = (): PluginDefinition<CronPluginConfig> => {
  let state: CronState | undefined;

  return definePlugin<CronPluginConfig>({
    id: 'cron',
    sdkVersion: CURRENT_SDK_VERSION,
    configSchema: CronConfigSchema,
    contributes: {
      // Called by the host before setup() to check name collisions, hence the empty fallback.
      tools: chatId => {
        if (!state || !isValidChatId(chatId)) return [];
        return createCronTools({ chatId, ...state });
      },
      promptHints: () => [{ placement: 'system', text: CRON_PROMPT_HINT }],
    },
    setup(ctx) {
      const { capabilities } = ctx;
      const log = capabilities.log;
      const store = createScheduleStore(capabilities.storage.rootDir);
      const { failed, skippedNames } = store.loadAll();
      // A bad file stays untouched on disk; that chat's tools fail until a human fixes it.
      for (const { chatId, error } of failed) {
        log.withFields({ chatId }).withError(error).error('Schedule file unreadable; leaving it untouched');
      }
      for (const name of skippedNames) log.withFields({ name }).warn('Ignoring file with an invalid chat id in schedule storage');

      const scheduler = createScheduler({
        store,
        config: ctx.config,
        isEnabled: chatId => ctx.isEnabledForChat?.(chatId) ?? capabilities.isEnabledForChat?.(chatId) ?? true,
        publish: (chatId, options) => capabilities.chat.publish(chatId, options),
        log,
      });
      state = { store, scheduler, config: ctx.config };
      scheduler.start();
    },
    stop() {
      state?.scheduler.stop();
      state = undefined;
    },
  });
};

export const cronPlugin = createCronPlugin();
