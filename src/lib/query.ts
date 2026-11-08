/**
 * Minimal data-fetching layer: `useQuery` re-runs when any of its tags is
 * invalidated via `invalidate(tag)`. Avoids pulling in a query library for a
 * local, single-user data store.
 */
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { errorMessage } from "./ipc";

export type Tag =
  | "activity"
  | "prefs"
  | "favorites"
  | "tasks"
  | "resources"
  | "commands"
  | "history"
  | "dorks"
  | "payloads"
  | "projects"
  | "findings"
  | "detections"
  | "executions"
  | "wordlists"
  | "cve"
  | "vt"
  | "ti"
  | "mcp"
  /** the MCP tool catalog: changes only with the policy or the on/off state */
  | "mcp-catalog"
  /** OSINT workspace data (investigations, entities, graphs, operations) */
  | "osint"
  /** OSINT collection operations only (a collection started; graphs are not affected yet) */
  | "osint-ops"
  /** project assets and discovery runs */
  | "assets"
  /** project vulnerabilities */
  | "vulns"
  /** project workflows and their runs */
  | "workflows"
  /** the finding library (templates) */
  | "templates"
  | "system";

const versions = new Map<Tag, number>();
const listeners = new Set<() => void>();
let snapshot = 0;

export function invalidate(...tags: Tag[]) {
  for (const t of tags) versions.set(t, (versions.get(t) ?? 0) + 1);
  snapshot++;
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function useTagVersion(tags: Tag[]): string {
  useSyncExternalStore(subscribe, () => snapshot);
  return tags.map((t) => versions.get(t) ?? 0).join(".");
}

export interface QueryState<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useQuery<T>(tags: Tag[], fn: () => Promise<T>, deps: unknown[] = [], enabled = true): QueryState<T> {
  const version = useTagVersion(tags);
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<{ data: T | undefined; error: string | null; loading: boolean }>({
    data: undefined,
    error: null,
    loading: enabled,
  });
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    if (!enabled) {
      setState((s) => ({ ...s, loading: false }));
      return;
    }
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    fnRef
      .current()
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((e) => alive && setState((s) => ({ data: s.data, error: errorMessage(e), loading: false })));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version, nonce, enabled, ...deps]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, reload };
}

/** Wraps an async mutation with pending state and consistent error reporting. */
export function useMutation<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  const [pending, setPending] = useState(false);
  const run = useCallback(
    async (...args: A): Promise<R> => {
      setPending(true);
      try {
        return await fn(...args);
      } finally {
        setPending(false);
      }
    },
    [fn],
  );
  return { run, pending };
}
