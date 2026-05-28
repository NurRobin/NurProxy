import { useCallback } from 'react';
import { useToast, errMessage } from '../components/toast-context';

interface UndoableOpts {
  /** Toast message, e.g. "Deleted app.example.com". */
  message: string;
  /** The real delete call — fired only if the window lapses without Undo. */
  doDelete: () => Promise<void>;
  /** Restore local state (the caller removed the item optimistically). */
  onUndo: () => void;
  failMessage?: string;
  windowMs?: number;
}

/**
 * Optimistic delete with an undo window. The caller removes the item from local
 * state immediately and provides `onUndo` to restore it. The actual API delete
 * fires after `windowMs` unless the user clicks Undo. (The backend has no
 * restore endpoint, so undo must prevent the call rather than reverse it.)
 */
export function useUndoableDelete() {
  const toast = useToast();
  return useCallback((opts: UndoableOpts) => {
    const { message, doDelete, onUndo, failMessage = 'Delete failed', windowMs = 6000 } = opts;
    let undone = false;
    const timer = setTimeout(async () => {
      if (undone) return;
      try { await doDelete(); } catch (e) { onUndo(); toast.error(errMessage(e, failMessage)); }
    }, windowMs);
    toast.push(message, 'info', {
      duration: windowMs,
      action: { label: 'Undo', onClick: () => { undone = true; clearTimeout(timer); onUndo(); } },
    });
  }, [toast]);
}
