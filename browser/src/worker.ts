import init, { WebVault, generatePassphrase } from "sos-wasm";
import * as Comlink from "comlink";

export { WebVault, generatePassphrase } from "sos-wasm";

export interface VaultWorker {
  WebVault(): Promise<WebVault>;
  generatePassphrase(words: number): Promise<[string, number]>;
}

// Requires top-level await experiment
await init();

Comlink.expose({ WebVault, generatePassphrase });
