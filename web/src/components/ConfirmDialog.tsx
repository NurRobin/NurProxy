import { useEffect, useState } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import Modal from './Modal';
import Button from './Button';
import { Input } from './Field';

interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: (freshPassword?: string) => void;
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  /** When set, the user must type this exact text to enable the confirm button. */
  confirmText?: string;
  freshPasswordLabel?: string;
}

export default function ConfirmDialog({ open, onClose, onConfirm, title, message, confirmLabel, danger, loading, confirmText, freshPasswordLabel }: ConfirmDialogProps) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState('');
  const [freshPassword, setFreshPassword] = useState('');
  useEffect(() => {
    if (!open) {
      setTyped('');
      setFreshPassword('');
    }
  }, [open]);

  const needsType = !!confirmText;
  const needsFreshPassword = !!freshPasswordLabel;
  const canConfirm = (!needsType || typed.trim() === confirmText) && (!needsFreshPassword || freshPassword.length > 0);

  return (
    <Modal open={open} onClose={onClose} title={title}>
      <p className="text-sm leading-relaxed text-fg-muted">{message}</p>
      {needsType && (
        <div className="mt-4">
          <label className="block text-sm text-fg-muted">
            <Trans i18nKey="confirm.typeToConfirm" values={{ text: confirmText }} components={[<span className="font-mono font-semibold text-fg" />]} />
          </label>
          <Input value={typed} onChange={(e) => setTyped(e.target.value)} className="mt-1.5 font-mono" autoFocus />
        </div>
      )}
      {needsFreshPassword && (
        <div className="mt-4">
          <label className="block text-sm text-fg-muted" htmlFor="confirm-fresh-password">{freshPasswordLabel}</label>
          <Input
            id="confirm-fresh-password"
            type="password"
            value={freshPassword}
            onChange={(event) => setFreshPassword(event.target.value)}
            className="mt-1.5"
            autoComplete="current-password"
            autoFocus={!needsType}
          />
        </div>
      )}
      <div className="mt-6 flex justify-end gap-3">
        <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant={danger ? 'danger' : 'primary'} onClick={() => onConfirm(needsFreshPassword ? freshPassword : undefined)} loading={loading} disabled={!canConfirm}>
          {confirmLabel ?? t('common.delete')}
        </Button>
      </div>
    </Modal>
  );
}
