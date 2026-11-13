// SPDX-License-Identifier: Apache-2.0
import type { TaxiiServer, TaxiiServerInput } from "@/lib/types";

/** The scheme, host and port a credential is sent to; null for an address that does not parse. */
export function originOf(url: string): string | null {
  try {
    return new URL(url.trim()).origin;
  } catch {
    return null;
  }
}

/** Whether saving this edit deletes the server's stored credential, as the backend does
 * (`ti::taxii::secret_name`): a credential is bound to its server's origin, its kind of
 * authentication and, for an API key, its header's name (in any case), and never follows the
 * server elsewhere. */
export function editDropsCredential(
  initial: Pick<TaxiiServer, "discoveryUrl" | "auth" | "headerName" | "credentialStored"> | null,
  next: Pick<TaxiiServerInput, "discoveryUrl" | "auth" | "headerName">,
): boolean {
  if (!initial?.credentialStored) return false;
  const to = originOf(next.discoveryUrl);
  if (to === null) return false;
  const header = (h: string) => h.trim().toLowerCase();
  return to !== originOf(initial.discoveryUrl) || next.auth !== initial.auth || (next.auth === "header" && header(next.headerName) !== header(initial.headerName));
}

/** Whether saving this edit removes the server's collections, as the backend does (`server_save`):
 * they belong to the origin the server leaves. */
export function editDropsCollections(initial: Pick<TaxiiServer, "discoveryUrl" | "collections"> | null, next: Pick<TaxiiServerInput, "discoveryUrl">): boolean {
  if (!initial || initial.collections.length === 0) return false;
  const to = originOf(next.discoveryUrl);
  return to !== null && to !== originOf(initial.discoveryUrl);
}

/** Whether an edit keeps a stored HTTP Basic password while changing the user name it was typed
 * for (the server and its kind of authentication stay, so the password is kept). */
export function editKeepsPasswordOfOtherUser(
  initial: Pick<TaxiiServer, "discoveryUrl" | "auth" | "headerName" | "credentialStored" | "username"> | null,
  next: Pick<TaxiiServerInput, "discoveryUrl" | "auth" | "headerName" | "username">,
): boolean {
  return !!initial?.credentialStored && initial.auth === "basic" && next.auth === "basic" && next.username.trim() !== initial.username && !editDropsCredential(initial, next);
}
