/**
 * INFINITEA-lab hardening (fork-only).
 *
 * 1. Live-runtime tools (anything that launches, attaches to, instruments, or
 *    drives a live process, device, browser, or debugger, plus arbitrary
 *    Cutter commands) are disabled unless REA_INFINITEA_RUNTIME_TOOLS=1.
 *    Disabled MCP tools are hidden from tools/list and rejected on call; the
 *    matching CLI commands fail before doing anything.
 * 2. `setup` is forced to --dry-run, and `uninstall`/`update` are refused,
 *    unless REA_INFINITEA_ALLOW_SETUP=1. Nothing writes ~/.claude*, ~/.codex,
 *    or other client configuration by default.
 */

export const INFINITEA_RUNTIME_ENV = "REA_INFINITEA_RUNTIME_TOOLS";
export const INFINITEA_SETUP_ENV = "REA_INFINITEA_ALLOW_SETUP";

/** MCP tool names (snake_case) gated as live-runtime. */
export const INFINITEA_RUNTIME_TOOLS: ReadonlySet<string> = new Set([
  // Frida instrumentation
  "list_frida_devices", "list_frida_processes", "start_frida_session",
  "instrument_with_frida", "load_frida_script", "unload_frida_script",
  "resume_frida_session", "close_frida_session", "frida_session_status",
  // Debuggers
  "start_gdb_session", "gdb_console", "gdb_session_status", "close_gdb_session",
  "start_rizin_debug_session", "rizin_debug_command",
  "rizin_debug_session_status", "close_rizin_debug_session",
  // Live native processes / UI
  "observe_native_ui", "capture_native_ui_scenario", "observe_native_calls",
  "capture_process_scenario",
  // Android devices over adb (inspect_adb_client only probes the local binary)
  "list_adb_devices", "inspect_adb_device", "list_adb_packages",
  "pull_adb_package", "read_adb_logcat", "inspect_adb_package", "pull_adb_file",
  "push_adb_file", "capture_adb_screen", "list_adb_processes",
  "list_adb_directory", "list_adb_features", "list_adb_services",
  "inspect_adb_display", "inspect_adb_window", "read_adb_setting",
  "collect_adb_bugreport", "resolve_adb_packages", "install_adb_package",
  "uninstall_adb_package", "start_adb_app", "start_adb_activity", "stop_adb_app",
  // Live browsers / Electron / V8 over CDP or Inspector
  "list_browser_targets", "inspect_web_page", "analyze_web_bundle",
  "observe_web_session", "discover_webmcp_tools", "capture_web_screenshot",
  "capture_browser_scenario", "observe_web_execution",
  "inspect_web_event_listeners", "list_electron_targets",
  "inspect_electron_page", "capture_electron_scenario",
  "list_javascript_runtime_targets", "observe_javascript_runtime",
  // Arbitrary commands in a live Cutter session
  "cutter_command",
]);

/** CLI command names (kebab-case) gated as live-runtime. */
export const INFINITEA_RUNTIME_CLI_COMMANDS: ReadonlySet<string> = new Set([
  ...[...INFINITEA_RUNTIME_TOOLS].map((name) => name.replaceAll("_", "-")),
  "debug-with-gdb", "debug-with-rizin", "capture-process",
]);

const enabled = (
  environment: Readonly<Record<string, string | undefined>>,
  key: string,
): boolean => environment[key] === "1";

export const infiniteaRuntimeToolsEnabled = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): boolean => enabled(environment, INFINITEA_RUNTIME_ENV);

export const infiniteaSetupAllowed = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): boolean => enabled(environment, INFINITEA_SETUP_ENV);

export const infiniteaRuntimeRefusal = (name: string): string =>
  `${name} is a live-runtime capability disabled in the INFINITEA fork. ` +
  `Set ${INFINITEA_RUNTIME_ENV}=1 for an explicitly authorized session.`;

interface GateableCli {
  command: (name: string, definition?: unknown, ...rest: unknown[]) => unknown;
}

/**
 * Wrap a CLI's command registration so gated commands fail closed and setup
 * stays a dry run. Call before any command is registered.
 */
export const installInfiniteaCliGate = <T extends GateableCli>(
  cli: T,
  environment: Readonly<Record<string, string | undefined>>,
): T => {
  const runtime = infiniteaRuntimeToolsEnabled(environment);
  const setup = infiniteaSetupAllowed(environment);
  const original = cli.command.bind(cli);
  cli.command = ((name: string, definition?: unknown, ...rest: unknown[]) => {
    const def = definition as
      | { run?: (context: Record<string, unknown>) => unknown }
      | undefined;
    if (typeof name !== "string" || def === undefined || typeof def.run !== "function")
      return original(name, definition, ...rest);
    const run = def.run;
    if (!runtime && INFINITEA_RUNTIME_CLI_COMMANDS.has(name))
      return original(name, { ...def, run: () => { throw new Error(infiniteaRuntimeRefusal(name)); } }, ...rest);
    if (!setup && (name === "uninstall" || name === "update"))
      return original(name, { ...def, run: () => { throw new Error(`${name} is disabled in the INFINITEA fork. Set ${INFINITEA_SETUP_ENV}=1 to allow configuration changes.`); } }, ...rest);
    if (!setup && name === "setup")
      return original(name, {
        ...def,
        run: (context: Record<string, unknown>) => {
          const options = (context.options ?? {}) as Record<string, unknown>;
          return run({ ...context, options: { ...options, dryRun: true, yes: false, installHopper: false } });
        },
      }, ...rest);
    return original(name, definition, ...rest);
  }) as T["command"];
  return cli;
};
