import { useEffect, useState } from 'react';
import Modal from './Modal';
import Button from './Button';
import { Input } from './Field';

interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  /** When set, the user must type this exact text to enable the confirm button. */
  confirmText?: string;
}

export default function ConfirmDialog({ open, onClose, onConfirm, title, message, confirmLabel = 'Confirm', danger, loading, confirmText }: ConfirmDialogProps) {
  const [typed, setTyped] = useState('');
  useEffect(() => { if (!open) setTyped(''); }, [open]);

  const needsType = !!confirmText;
  const canConfirm = !needsType || typed.trim() === confirmText;

  return (
    <Modal open={open} onClose={onClose} title={title}>
      <p className="text-sm leading-relaxed text-fg-muted">{message}</p>
      {needsType && (
        <div className="mt-4">
          <label className="block text-sm text-fg-muted">
            Type <span className="font-mono font-semibold text-fg">{confirmText}</span> to confirm
          </label>
          <Input value={typed} onChange={(e) => setTyped(e.target.value)} className="mt-1.5 font-mono" autoFocus />
        </div>
      )}
      <div className="mt-6 flex justify-end gap-3">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} loading={loading} disabled={!canConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
