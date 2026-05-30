// copyText copies text to the clipboard, working in BOTH secure and insecure
// contexts. The async Clipboard API (navigator.clipboard) is only defined when
// the page is a secure context — HTTPS, or http on localhost. A dashboard
// reached over plain http on a LAN IP or via a reverse proxy is NOT secure, so
// navigator.clipboard is undefined and a naive writeText throws. We fall back to
// a hidden-textarea + execCommand('copy'), which still works there.
//
// Returns true on success so callers can decide whether to show "copied"
// feedback or a manual-copy hint.
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through to the legacy path (e.g. permission quirk)
    }
  }

  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    // Keep it out of view and prevent the page from scrolling/zooming to it.
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.left = '0';
    ta.style.width = '1px';
    ta.style.height = '1px';
    ta.style.opacity = '0';
    ta.setAttribute('readonly', '');
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
