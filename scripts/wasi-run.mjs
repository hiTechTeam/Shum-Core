// Runs a WebAssembly (wasm32-wasip1) test binary in Node.js, so Shum-Core's
// tests and protocol vectors run inside WebAssembly as in the browser.
// Used as the Cargo runner by scripts/test-wasm.sh. Only the Shum-Core folder
// (SHUM_WASI_ROOT) is visible, for the protocol vectors the tests read.
import { readFile } from "node:fs/promises";
import { argv, env, exit } from "node:process";
import { WASI } from "node:wasi";

const root = env.SHUM_WASI_ROOT;
const preopens = root ? { [root]: root } : {};
const wasi = new WASI({ version: "preview1", args: argv.slice(2), env, preopens, returnOnExit: true });
const module = await WebAssembly.compile(await readFile(argv[2]));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
exit(wasi.start(instance));
