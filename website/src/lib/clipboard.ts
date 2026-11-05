/** Copies text; resolves false when the clipboard is unavailable or the browser refuses. */
export async function copyText(text: string, clipboard: Pick<Clipboard, "writeText"> | undefined = typeof navigator !== "undefined" ? navigator.clipboard : undefined): Promise<boolean> {
  if (!clipboard?.writeText) return false;
  try {
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
