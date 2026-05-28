import { createContext, useContext } from 'react';

export type ToastVariant = 'error' | 'success' | 'info';

export interface ToastRecord {
  id: number;
  message: string;
  variant: ToastVariant;
  at: string; // ISO timestamp
}

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastOptions {
  action?: ToastAction;
  /** Override the auto-dismiss duration in ms. */
  duration?: number;
}

export interface ToastContextValue {
  push: (message: string, variant?: ToastVariant, opts?: ToastOptions) => void;
  error: (message: string) => void;
  success: (message: string) => void;
  /** Recent notifications (newest first), retained after the transient toast fades. */
  history: ToastRecord[];
  /** Count of unseen errors since the notification center was last opened. */
  unseen: number;
  markSeen: () => void;
  clearHistory: () => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

/** Pulls a readable message out of an API error (strips the "API error 500:" prefix). */
export function errMessage(err: unknown, fallback = 'Something went wrong'): string {
  if (err instanceof Error) {
    return err.message.replace(/^API error \d+:\s*/, '').trim() || fallback;
  }
  return fallback;
}
