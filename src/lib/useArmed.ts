import { useEffect, useState } from "react";

/**
 * Safety delay for approval buttons: returns false for `delayMs` after `key` changes (a new
 * request came to the front, or the list of requests changed), so a click aimed at one request
 * cannot approve another that just moved under the pointer.
 */
export function useArmed(key: string | undefined, delayMs = 1000): boolean {
  const [armedKey, setArmedKey] = useState<string | undefined>();
  useEffect(() => {
    setArmedKey(undefined);
    if (key === undefined) return;
    const t = setTimeout(() => setArmedKey(key), delayMs);
    return () => clearTimeout(t);
  }, [key, delayMs]);
  return key !== undefined && armedKey === key;
}
