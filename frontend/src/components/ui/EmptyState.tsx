import type { ReactNode } from 'react';

interface EmptyStateProps {
  message?: string;
  children?: ReactNode;
  icon?: ReactNode;
}

export function EmptyState({ message, children, icon }: EmptyStateProps) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state-icon">{icon}</div>}
      {message && <p>{message}</p>}
      {children}
    </div>
  );
}
