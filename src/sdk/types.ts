export const CURRENT_SDK_VERSION = 1;

export interface PluginLogger {
  log(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  debug(message: string, fields?: Record<string, unknown>): void;
  withFields(fields: Record<string, unknown>): PluginLogger;
  withError(error: unknown): PluginLogger;
}

export interface HttpRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  body: unknown;
  params?: Record<string, string>;
}

export interface HttpResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string | Buffer | Record<string, unknown>;
}

export type HttpHandler = (req: HttpRequest) => Promise<HttpResponse | void> | HttpResponse | void;

export interface HttpRoute {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | '*';
  path: string;
  handler: HttpHandler;
}

export interface ChatPublishOptions {
  kind?: string;
  text: string;
  wake?: boolean;
}

export interface PromptHint {
  placement: 'system' | 'lateBinding';
  text: string;
}

export interface PluginToolResult {
  content: string;
  requiresFollowUp?: boolean;
}

/**
 * Opt-in for slow tools. If `execute` has not settled after `afterMs`, the host
 * moves the still-running call into a background task bounded by `timeoutMs`
 * and returns a task id to the model at once; the result reaches the chat later
 * as a runtime event that wakes the bot. A call that settles in time returns
 * inline, exactly as without this field.
 */
export interface PluginToolBackground {
  afterMs: number;
  timeoutMs: number;
}

export interface PluginTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  background?: PluginToolBackground;
  /**
   * `signal` is passed only for tools that declare `background` and aborts when
   * the host abandons the call (timeout, cancellation, shutdown). Honouring it
   * is optional; an ignored abort just discards the late result.
   */
  execute(input: unknown, signal?: AbortSignal): Promise<PluginToolResult> | PluginToolResult;
}

export interface PluginSceneDefinition {
  id: string;
  hint?: string;
  idleTimeoutMs?: number;
}

export interface PluginExtensionPoints {
  tools?: PluginTool[] | ((chatId: string, chatPluginConfig?: unknown) => PluginTool[] | undefined);
  memoryBackend?: unknown;
  mediaResolvers?: unknown[];
  httpRoutes?: HttpRoute[];
  scenes?: PluginSceneDefinition[];
  promptHints?: (chatId: string) => PromptHint[] | undefined;
}

export interface PluginCapabilities {
  callModel(
    modelName: string,
    prompt: string | { system?: string; user: string },
    options?: { timeoutSec?: number; dumpId?: string },
  ): Promise<string>;

  ask(
    chatId: string,
    options: {
      question: string;
      choices: string[];
      timeoutMs?: number;
    },
  ): Promise<{ choice: string; reason?: string }>;

  isEnabledForChat?(chatId: string): boolean;

  http: {
    route(route: HttpRoute): void;
  };

  chat: {
    publish(chatId: string, options: ChatPublishOptions): Promise<void> | void;
  };

  scene: {
    enter(chatId: string, sceneId: string): void;
    exit(chatId: string, sceneId: string): void;
    note(chatId: string, sceneId: string, text: string | null): void;
  };

  storage: {
    rootDir: string;
  };

  log: PluginLogger;

  media: {
    send(chatId: string, media: { kind: 'image' | 'audio'; [key: string]: unknown }): Promise<void>;
  };
}

export interface PluginContext<TConfig = unknown> {
  config: TConfig;
  capabilities: PluginCapabilities;
  isEnabledForChat?(chatId: string): boolean;
}

export interface PluginDefinition<TConfig = unknown> {
  id: string;
  sdkVersion: number;
  configSchema?: unknown;
  contributes?: PluginExtensionPoints;
  setup(ctx: PluginContext<TConfig>): Promise<void> | void;
  stop?(): Promise<void> | void;
}

export const definePlugin = <TConfig = unknown>(
  def: PluginDefinition<TConfig>,
): PluginDefinition<TConfig> => def;
