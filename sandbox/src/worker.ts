import init, { loadVault, newVault, WebVault } from "sos-wasm";
import * as Comlink from "comlink";

export interface VaultWorker {
  // NOTE: For types we use `Array` so deserialization
  // NOTE: works on the webassembly side but really these
  // NOTE: should be Uint8Array
  newVault(label: string, value: number[]): Promise<WebVault>;
  loadVault(value: number[]): Promise<WebVault>;
}

// For top-level await typescript wants `target` to be es2017
// but this generates a "too much recursion" runtime error so
// we avoid top-level await for now
void (async function () {
  console.log("Worker is initializing...");
  await init();
})();

Comlink.expose({
  loadVault,
  newVault,
});
