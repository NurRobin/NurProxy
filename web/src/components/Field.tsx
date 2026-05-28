import { useState, type InputHTMLAttributes, type SelectHTMLAttributes, type TextareaHTMLAttributes, type ReactNode } from 'react';
import HelpTip from './HelpTip';

const fieldBase =
  'block w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-faint transition-colors focus:border-accent focus-visible:outline-none focus:ring-2 focus:ring-accent/30';

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
        {show ? (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.22A10.5 10.5 0 0 0 1.5 12s3.75 7.5 10.5 7.5c1.6 0 3.06-.36 4.34-.95M9.88 5.09A10.6 10.6 0 0 1 12 4.5c6.75 0 10.5 7.5 10.5 7.5a18 18 0 0 1-2.76 3.86M6.1 6.1l11.8 11.8M3 3l18 18" />
          </svg>
        ) : (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M2.04 12.32a1 1 0 0 1 0-.64C3.42 7.51 7.36 4.5 12 4.5s8.58 3.01 9.96 7.18a1 1 0 0 1 0 .64C20.58 16.49 16.64 19.5 12 19.5s-8.58-3.01-9.96-7.18z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
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

export function Checkbox({ className = '', label, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
      <input
        type="checkbox"
        className={`h-4 w-4 rounded border-border accent-[var(--accent)] ${className}`}
        {...rest}
      />
      {label}
    </label>
  );
}
