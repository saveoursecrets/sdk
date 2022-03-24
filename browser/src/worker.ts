import init, { WebVault, generatePassphrase } from "sos-wasm";
import * as Comlink from "comlink";

export { WebVault, generatePassphrase } from "sos-wasm";

export interface VaultWorker {
  WebVault(): Promise<WebVault>;
  generatePassphrase(words: number): Promise<[string, number]>;
}

// For top-level await typescript wants `target` to be es2017
// but this generates a "too much recursion" runtime error so
// we avoid top-level await for now
void (async function () {
  console.log("Worker is initializing...");
  await init();
})();

Comlink.expose({ WebVault, generatePassphrase });
