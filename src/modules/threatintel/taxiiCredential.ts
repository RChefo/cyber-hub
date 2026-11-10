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
 * (`commands/taxii.rs`): a credential never follows its server to another origin or to another
 * kind of authentication. */
export function editDropsCredential(initial: Pick<TaxiiServer, "discoveryUrl" | "auth" | "credentialStored"> | null, next: Pick<TaxiiServerInput, "discoveryUrl" | "auth">): boolean {
  if (!initial?.credentialStored) return false;
  const to = originOf(next.discoveryUrl);
  return to !== null && (to !== originOf(initial.discoveryUrl) || next.auth !== initial.auth);
}
