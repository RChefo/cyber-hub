import { useCallback, useEffect, useState } from "react";
import { config } from "./config";
import { loadLatestRelease, type ReleaseState } from "./releases";

export function useLatestRelease(): ReleaseState & { retry: () => void } {
  const [state, setState] = useState<ReleaseState>(config.repository ? { kind: "loading" } : { kind: "not-configured" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!config.repository) return;
    let live = true;
    loadLatestRelease(config.repository, config.apiBase).then((s) => live && setState(s));
    return () => {
      live = false;
    };
  }, [attempt]);
  const retry = useCallback(() => {
    setState({ kind: "loading" });
    setAttempt((a) => a + 1);
  }, []);
  return { ...state, retry };
}
