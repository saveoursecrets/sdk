import { WebVault, generatePassphrase } from "sos-wasm";
import * as Comlink from "comlink";

export interface VaultWorker {
  WebVault(): Promise<WebVault>;
  generatePassphrase(words: number): Promise<[string, number]>;
}

Comlink.expose({ WebVault, generatePassphrase });
