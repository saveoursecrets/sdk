import { User, Signature } from "../types";

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
  ): Promise<unknown> {
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
    return response.json();
  }

  // Load the vault list for a user.
  async loadVaults(user: User): Promise<string[]> {
    const url = `${this.url}/accounts/${user.address}`;
    const response = await fetch(url);
    return response.json();
  }

  // Load the encrypted vault buffer for a user.
  async getVault(user: User, id: string): Promise<ArrayBuffer> {
    const url = `${this.url}/accounts/${user.address}/vaults/${id}`;
    const response = await fetch(url);
    return response.arrayBuffer();
  }
}

const api = new VaultApi("http://localhost:5053/api");

export default api;
