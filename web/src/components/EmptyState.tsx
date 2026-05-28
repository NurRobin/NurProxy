import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}

export default function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-700 bg-gray-900/50 px-6 py-16 text-center">
      {icon && <div className="mb-4 text-gray-500">{icon}</div>}
      <h3 className="text-lg font-semibold text-gray-200">{title}</h3>
      {description && <p className="mt-2 max-w-sm text-sm text-gray-400">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
