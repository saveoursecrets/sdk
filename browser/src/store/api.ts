import { Account, Signature } from "../types";

const MIME_TYPE_VAULT = "application/sos+vault";

function bearer(signature: Signature): string {
  return `Bearer ${btoa(JSON.stringify(signature))}`;
}

// Client consumer of the server API.
export class VaultApi {
  url: string;

  constructor(url: string) {
    this.url = url;
  }

  // Create a new account.
  async createAccount(
    signature: Signature,
    vault: Uint8Array
  ): Promise<boolean> {
    const url = `${this.url}/accounts`;
    const body = new Blob([vault.buffer]);
    const headers = {
      authorization: bearer(signature),
      "content-type": MIME_TYPE_VAULT,
    };
    const response = await fetch(url, {
      method: "POST",
      body,
      mode: "cors",
      headers,
    });
    return response.ok;
  }

  // Generate a login challenge to sign.
  async loginChallenge(
    signature: Signature,
    message: Uint8Array
  ): Promise<[string, Uint8Array]> {
    const url = `${this.url}/auth`;
    const body = new Blob([message.buffer]);
    const headers = {
      authorization: bearer(signature),
    };
    const response = await fetch(url, {
      method: "POST",
      body,
      mode: "cors",
      headers,
    });
    const result = await response.json();
    const [uuid, challenge] = result;
    return [uuid, new Uint8Array(challenge)];
  }

  // Send a login challenge response.
  async loginResponse(
    signature: Signature,
    uuid: string,
    message: Uint8Array
  ): Promise<void> {
    const url = `${this.url}/auth/${uuid}`;
    const body = new Blob([message.buffer]);
    const headers = {
      authorization: bearer(signature),
    };
    const response = await fetch(url, {
      method: "POST",
      body,
      mode: "cors",
      headers,
    });

    console.log("Response result", response.ok);
  }

  // Load the vault list for a user.
  async loadVaults(account: Account): Promise<string[]> {
    const url = `${this.url}/accounts/${account.address}`;
    const response = await fetch(url);
    return response.json();
  }

  // Load the encrypted vault buffer for a user.
  async getVault(account: Account, id: string): Promise<ArrayBuffer> {
    const url = `${this.url}/accounts/${account.address}/vaults/${id}`;
    const response = await fetch(url);
    return response.arrayBuffer();
  }
}

const api = new VaultApi("http://localhost:5053/api");

export default api;
