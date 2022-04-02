import init, { WebVault, generatePassphrase } from "sos-wasm";
import * as Comlink from "comlink";

export { WebVault, generatePassphrase } from "sos-wasm";

console.log("WORKER IS INITIALIZING...");

void (async function () {
  // Requires top-level await experiment
  await init();
  console.log("Worker finished initializing");
  self.postMessage({ ready: true });
})();

Comlink.expose({ WebVault, generatePassphrase });
