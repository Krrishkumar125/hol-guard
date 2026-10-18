// Real pinned SDK hooks + Bash tools; no model, account or operator config.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [sdkRoot, configurationPath] = process.argv.slice(2);
const configuration = JSON.parse(readFileSync(configurationPath, "utf8"));
const sdk = join(sdkRoot, "node_modules", configuration.harness === "pi"
  ? "@earendil-works/pi-coding-agent" : "@oh-my-pi/pi-coding-agent");
const version = JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")).version;
if (version !== configuration.expectedVersion) throw Error("unpinned OMP SDK");
const { handlers } = await import(pathToFileURL(configuration.routingModule).href);
const sessionManager = {
  getCwd: () => configuration.workspace,
  getSessionId: () => "bound-bash-sdk-fixture",
};
const extension = {
  path: configuration.routingModule, resolvedPath: configuration.routingModule, handlers,
  flags: new Map(), commands: new Map(), shortcuts: new Map(), tools: new Map(),
};
if (configuration.harness === "pi") {
  const load = (path: string) => import(pathToFileURL(join(sdk, "dist/core", path)).href);
  const { ExtensionRunner } = await load("extensions/runner.js");
  const { AgentSession } = await load("agent-session.js");
  const { createBashTool } = await load("tools/bash.js");
  const runner = new ExtensionRunner([extension], {}, configuration.workspace, sessionManager, {});
  const owner = { agent: {}, _extensionRunner: runner };
  AgentSession.prototype._installAgentToolHooks.call(owner);
  const args = structuredClone(configuration.input);
  const hook = await owner.agent.beforeToolCall({
    toolCall: { id: configuration.callId, name: "bash" }, args,
  });
  if (hook !== undefined) throw Error("Pi mutation route returned an unexpected decision");
  try {
    const result = await createBashTool(configuration.workspace).execute(configuration.callId, args);
    console.log(JSON.stringify({ version, result, originalInput: configuration.input }));
  } catch (error) {
    console.log(JSON.stringify({ version, sdkError: String(error), originalInput: configuration.input }));
  }
  process.exit(0);
}
const load = (path: string) => import(pathToFileURL(join(sdk, "src", path)).href);
const { Settings, withActiveSettings } = await load("config/settings.ts");
const { ExtensionRunner } = await load("extensibility/extensions/runner.ts");
const { ExtensionToolWrapper } = await load("extensibility/extensions/wrapper.ts");
const { BashTool } = await load("tools/bash.ts");
const settings = Settings.isolated();
const runner = new ExtensionRunner(
  [extension], {}, configuration.workspace, sessionManager, {}, undefined, settings,
);
const tool = new BashTool({
  cwd: configuration.workspace, hasUI: false, settings, sessionManager,
  getSessionId: sessionManager.getSessionId, getSessionFile: () => null,
});
const wrapped = new ExtensionToolWrapper(tool, runner);
const result = await withActiveSettings(settings, () => wrapped.execute(
  configuration.callId, configuration.input, undefined, undefined, { settings },
));
console.log(JSON.stringify({ version, result, originalInput: configuration.input }));
await runner.shutdown();
