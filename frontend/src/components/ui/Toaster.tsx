import { useToast } from '../../contexts/ToastContext';
import { CloseIcon } from '../icons/Icons';

export function Toaster() {
  const { toasts, dismiss } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div
      className="toaster"
      role="region"
      aria-label="Notifications"
      aria-live="polite"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`toast toast-${t.tone}`}
          role={t.tone === 'error' || t.tone === 'warning' ? 'alert' : 'status'}
        >
          <div className="toast-body">
            {t.title && <div className="toast-title">{t.title}</div>}
            <div className="toast-message">{t.message}</div>
          </div>
          <button
            type="button"
            className="toast-close"
            aria-label="Dismiss notification"
            onClick={() => dismiss(t.id)}
          >
            <CloseIcon />
          </button>
        </div>
      ))}
    </div>
  );
}
