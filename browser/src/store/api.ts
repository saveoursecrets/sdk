import { Account, Signature, Summary, AeadPack } from "../types";
import { encode, toHexString } from "../utils";
import { WebSigner } from "sos-wasm";

const MIME_TYPE_VAULT = "application/sos+vault";
const MIME_TYPE_PATCH = "application/sos+patch";

function base64encode(signature: Signature): string {
  return btoa(JSON.stringify(signature));
}

function bearer(signature: Signature): string {
  return `Bearer ${base64encode(signature)}`;
}

function signedMessageHeader(message: Uint8Array): string {
  // NOTE: btoa() requires a "binary string", raw bytes won't
  // NOTE: be decoded correctly on the server so we must
  // NOTE: convert to a string before base64 encoding.
  const msg = message.reduce((prev: string, num: number) => {
    prev += String.fromCharCode(num);
    return prev;
  }, "");
  return btoa(msg);
}

// Client consumer of the server API.
export class VaultApi {
  url: string;

  constructor(url: string) {
    this.url = url;
  }

  // Helper to sign a random message used for requests
  // that do not have a body payload to sign (GET, DELETE).
  async selfSigned(signer: WebSigner): Promise<[Signature, Uint8Array]> {
    const message = new Uint8Array(32);
    self.crypto.getRandomValues(message);
    const signature = await signer.sign(Array.from(message));
    return [signature, message];
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
      method: "PUT",
      mode: "cors",
      headers,
      body,
    });
    return response.ok;
  }

  // Generate a login challenge to sign.
  async loginChallenge(
    signature: Signature,
    message: Uint8Array
  ): Promise<[string, Uint8Array]> {
    const url = `${this.url}/auth`;
    const headers = {
      authorization: bearer(signature),
      "x-signed-message": signedMessageHeader(message),
    };
    const response = await fetch(url, {
      method: "GET",
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
  ): Promise<Summary[]> {
    const url = `${this.url}/auth/${uuid}`;
    const headers = {
      authorization: bearer(signature),
      "x-signed-message": signedMessageHeader(message),
    };
    const response = await fetch(url, {
      method: "GET",
      mode: "cors",
      headers,
    });

    return response.json();
  }

  /* ACCOUNT */

  // Load the encrypted vault buffer for a user.
  async getVault(account: Account, vaultId: string): Promise<ArrayBuffer> {
    const [signature, message] = await this.selfSigned(account.signer);
    const url = `${this.url}/vaults/${vaultId}`;
    const headers = {
      authorization: bearer(signature),
      "x-signed-message": signedMessageHeader(message),
    };
    const response = await fetch(url, {
      method: "GET",
      mode: "cors",
      headers,
    });
    return response.arrayBuffer();
  }

  // Save the buffer for an entire vault.
  async saveVault(
    account: Account,
    vaultId: string,
    vault: Uint8Array,
    changeSequence: number
  ): Promise<Response> {
    const signature = await account.signer.sign(Array.from(vault));
    const url = `${this.url}/vaults/${vaultId}`;
    const body = new Blob([vault.buffer]);
    const headers = {
      authorization: bearer(signature),
      "content-type": MIME_TYPE_VAULT,
      "x-change-sequence": changeSequence.toString(),
    };
    const response = await fetch(url, {
      method: "POST",
      mode: "cors",
      headers,
      body,
    });
    return response;
  }

  // Apply a changeset to patch a vault.
  async patchVault(
    account: Account,
    vaultId: string,
    patch: Uint8Array,
    changeSequence: number
  ): Promise<Response> {
    const signature = await account.signer.sign(Array.from(patch));
    const url = `${this.url}/vaults/${vaultId}`;
    const body = new Blob([patch.buffer]);
    const headers = {
      authorization: bearer(signature),
      "content-type": MIME_TYPE_PATCH,
      "x-change-sequence": changeSequence.toString(),
    };
    const response = await fetch(url, {
      method: "PATCH",
      mode: "cors",
      headers,
      body,
    });
    return response;
  }

  // Send an encrypted secret payload for a create or update operation.
  async sendSecretPayload(
    account: Account,
    changeSequence: number,
    vaultId: string,
    secretId: string,
    secret: [AeadPack, AeadPack],
    method: string
  ): Promise<Response> {
    // Convert the tuple to JSON and sign the resulting bytes
    const body: Uint8Array = encode(JSON.stringify(secret));
    const signature = await account.signer.sign(Array.from(body));

    const url = `${this.url}/vaults/${vaultId}/secrets/${secretId}`;
    const headers = {
      authorization: bearer(signature),
      "x-change-sequence": changeSequence.toString(),
    };

    const response = await fetch(url, {
      method,
      mode: "cors",
      headers,
      body,
    });
    return response;
  }

  // Create a secret.
  async createSecret(
    account: Account,
    changeSequence: number,
    vaultId: string,
    secretId: string,
    secret: [AeadPack, AeadPack]
  ): Promise<Response> {
    return this.sendSecretPayload(
      account,
      changeSequence,
      vaultId,
      secretId,
      secret,
      "PUT"
    );
  }

  // Read a secret.
  async readSecret(
    account: Account,
    changeSequence: number,
    vaultId: string,
    secretId: string
  ): Promise<Response> {
    const [signature, message] = await this.selfSigned(account.signer);
    const url = `${this.url}/vaults/${vaultId}/secrets/${secretId}`;
    const headers = {
      authorization: bearer(signature),
      "x-signed-message": signedMessageHeader(message),
      "x-change-sequence": changeSequence.toString(),
    };
    const response = await fetch(url, {
      method: "GET",
      mode: "cors",
      headers,
    });
    return response;
  }

  // Update a secret.
  async updateSecret(
    account: Account,
    changeSequence: number,
    vaultId: string,
    secretId: string,
    secret: [AeadPack, AeadPack]
  ): Promise<Response> {
    return this.sendSecretPayload(
      account,
      changeSequence,
      vaultId,
      secretId,
      secret,
      "POST"
    );
  }

  // Delete a secret.
  async deleteSecret(
    account: Account,
    changeSequence: number,
    vaultId: string,
    secretId: string
  ): Promise<Response> {
    const [signature, message] = await this.selfSigned(account.signer);
    const url = `${this.url}/vaults/${vaultId}/secrets/${secretId}`;
    const headers = {
      authorization: bearer(signature),
      "x-signed-message": signedMessageHeader(message),
      "x-change-sequence": changeSequence.toString(),
    };
    const response = await fetch(url, {
      method: "DELETE",
      mode: "cors",
      headers,
    });
    return response;
  }

  // Get an event source handler for the changes stream.
  async getChanges(account: Account): Promise<EventSource> {
    const [signature, message] = await this.selfSigned(account.signer);
    const token = encodeURIComponent(base64encode(signature));
    const url = `${this.url}/changes?message=${toHexString(
      message
    )}&token=${token}`;
    return new EventSource(url, { withCredentials: true });
  }
}

const api = new VaultApi("http://localhost:5053/api");

export default api;
