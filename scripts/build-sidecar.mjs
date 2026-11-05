// Builds the `cyberhub-mcp` MCP server for the target and checks it (`--version`), so
// `tauri build` stops before packaging if the server cannot be built, and stages a copy at
// src-tauri/binaries/cyberhub-mcp-<target triple>[.exe] for manual use.
//
// The installers do not take the staged copy: `cyberhub-mcp` is a `[[bin]]` of the app crate, and
// the Tauri bundler ships every binary of the crate next to the Cyber Hub executable (declaring it
// again in bundle.externalBin put the same file into the MSI twice, which WiX refuses):
//   Windows  <install dir>\cyberhub-mcp.exe
//   Linux    /usr/bin/cyberhub-mcp (deb, rpm), usr/bin inside the AppImage
// Supported platforms are Windows x64 and Linux x64; macOS targets are refused.
// The app looks for it there (src-tauri/src/commands/mcp.rs, server_path).
//
// `tauri build` runs this script from beforeBuildCommand with TAURI_ENV_TARGET_TRIPLE and
// TAURI_ENV_DEBUG set. It can also be run by hand: `node scripts/build-sidecar.mjs [--target <triple>] [--debug]`.
// The sidecar is built without the `provisioning` feature: the developer-only `cyberhub-keys`
// tool is never part of it.
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const tauriDir = join(root, "src-tauri");
const NAME = "cyberhub-mcp";

const args = process.argv.slice(2);
const argTarget = args.includes("--target") ? args[args.indexOf("--target") + 1] : undefined;
const debug = args.includes("--debug") || process.env.TAURI_ENV_DEBUG === "true";

function run(cmd, cmdArgs, opts = {}) {
  const r = spawnSync(cmd, cmdArgs, { stdio: "inherit", ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    console.error(`build-sidecar: ${cmd} ${cmdArgs.join(" ")} failed (exit ${r.status})`);
    process.exit(r.status ?? 1);
  }
}

const hostTriple = (() => {
  const r = spawnSync("rustc", ["-vV"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error("build-sidecar: rustc -vV failed; is Rust installed?");
  return /^host: (\S+)$/m.exec(r.stdout)[1];
})();
const triple = argTarget || process.env.TAURI_ENV_TARGET_TRIPLE || hostTriple;
if (!/^[a-z0-9_]+(-[a-z0-9_.]+){2,3}$/.test(triple)) throw new Error(`build-sidecar: unexpected target triple ${triple}`);
if (triple.includes("apple-darwin")) throw new Error("build-sidecar: macOS is not a supported platform for Cyber Hub");

const ext = triple.includes("windows") ? ".exe" : "";
const profile = debug ? "debug" : "release";
const targetDir = process.env.CARGO_TARGET_DIR || join(tauriDir, "target");

// The nested cargo build must not see the Tauri CLI's configuration overrides.
const env = { ...process.env };
delete env.TAURI_CONFIG;

/** Build for one real target triple and return the path of the produced executable. */
function build(t) {
  const cargoArgs = ["build", "--locked", "--bin", NAME];
  if (!debug) cargoArgs.push("--release");
  // building for the host without --target shares the build cache with `tauri build`
  const explicit = t !== hostTriple;
  if (explicit) cargoArgs.push("--target", t);
  run("cargo", cargoArgs, { cwd: tauriDir, env });
  const out = join(targetDir, ...(explicit ? [t] : []), profile, NAME + (t.includes("windows") ? ".exe" : ""));
  if (!existsSync(out)) throw new Error(`build-sidecar: expected ${out} after the build`);
  return out;
}

const built = build(triple);

const binDir = join(tauriDir, "binaries");
mkdirSync(binDir, { recursive: true });
const staged = join(binDir, `${NAME}-${triple}${ext}`);
rmSync(staged, { force: true });
copyFileSync(built, staged);
if (!ext) chmodSync(staged, 0o755);

const size = statSync(staged).size;
if (size < 64 * 1024) throw new Error(`build-sidecar: ${staged} is only ${size} bytes`);

// When the staged binary runs on this machine, check that it is the MCP server of this version.
const runnable = triple === hostTriple;
if (runnable) {
  const v = spawnSync(staged, ["--version"], { encoding: "utf8" });
  const expected = `${NAME} ${JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version}`;
  if (v.status !== 0 || v.stdout.trim() !== expected) {
    console.error(`build-sidecar: ${staged} --version printed ${JSON.stringify(v.stdout.trim())}, expected ${JSON.stringify(expected)}`);
    process.exit(1);
  }
}
console.log(`build-sidecar: staged ${staged} (${(size / 1048576).toFixed(1)} MB, ${profile}${runnable ? ", version checked" : ""})`);
