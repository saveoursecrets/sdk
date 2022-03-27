import {User} from '../types';

// Client consumer of the server API.
export class VaultApi {
  url: string;

  constructor(url: string) {
    this.url = url;
  }

  // Load the vault list for a user.
  async loadVaults(user: User): Promise<string[]> {
    const url = `${this.url}/users/${user.address}`;
    const response = await fetch(url);
    return response.json();
  }

  // Load the encrypted vault buffer for a user.
  async getVault(user: User, id: string): Promise<ArrayBuffer> {
    const url = `${this.url}/users/${user.address}/vaults/${id}`;
    const response = await fetch(url);
    return response.arrayBuffer();
  }
}

const api = new VaultApi("http://localhost:5053/api");

export default api;
