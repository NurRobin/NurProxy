import { useState, type InputHTMLAttributes, type SelectHTMLAttributes, type TextareaHTMLAttributes, type ReactNode } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import HelpTip from './HelpTip';

const fieldBase =
  'block w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-faint transition-colors focus:border-accent focus-visible:outline-none focus:ring-2 focus:ring-accent/30 disabled:cursor-not-allowed disabled:opacity-50';

export function Input({ className = '', ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${fieldBase} ${className}`} {...rest} />;
}

/** Password/secret input with a built-in show/hide toggle (consistent SVG eye). */
export function PasswordInput({ className = '', ...rest }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <Input type={show ? 'text' : 'password'} className={`pr-10 ${className}`} {...rest} />
      <button
        type="button"
        onClick={() => setShow((v) => !v)}
        aria-label={show ? 'Hide' : 'Show'}
        title={show ? 'Hide' : 'Show'}
        className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1.5 text-fg-faint transition-colors hover:text-fg"
      >
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

export function Textarea({ className = '', ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`${fieldBase} ${className}`} {...rest} />;
}

export function Select({ className = '', children, ...rest }: SelectHTMLAttributes<HTMLSelectElement> & { children: ReactNode }) {
  return (
    <select className={`${fieldBase} ${className}`} {...rest}>
      {children}
    </select>
  );
}

interface FieldProps {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  /** Slug in the wiki glossary this term links to. */
  help?: string;
  children: ReactNode;
  className?: string;
}

/** A labelled field row with an optional inline help affordance and hint text. */
export function Field({ label, htmlFor, hint, help, children, className = '' }: FieldProps) {
  return (
    <div className={className}>
      <div className="mb-1 flex items-center gap-1.5">
        <label htmlFor={htmlFor} className="text-sm font-medium text-fg">
          {label}
        </label>
        {help && <HelpTip term={help} />}
      </div>
      {children}
      {hint && <p className="mt-1.5 text-xs text-fg-faint">{hint}</p>}
    </div>
  );
}

export function Checkbox({ className = '', label, disabled, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label
      className={`flex items-center gap-2 text-sm text-fg ${
        disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'
      }`}
    >
      <input
        type="checkbox"
        disabled={disabled}
        className={`h-4 w-4 rounded border-border accent-[var(--accent)] ${disabled ? 'cursor-not-allowed' : ''} ${className}`}
        {...rest}
      />
      {label}
    </label>
  );
}
