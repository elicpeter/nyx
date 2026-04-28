import { useTheme } from '../../contexts/ThemeContext';
import { MoonIcon, SunIcon } from '../icons/Icons';

const LABELS: Record<string, string> = {
  light: 'Light theme',
  dark: 'Dark theme',
  system: 'System theme',
};

export function ThemeToggle() {
  const { preference, resolved, cycle } = useTheme();
  const label = LABELS[preference];
  const next =
    preference === 'light'
      ? 'dark'
      : preference === 'dark'
        ? 'system'
        : 'light';

  return (
    <button
      type="button"
      className="btn btn-icon btn-ghost theme-toggle"
      onClick={cycle}
      aria-label={`${label} (click for ${LABELS[next]})`}
      title={`${label} — click to switch`}
    >
      {resolved === 'dark' ? <MoonIcon /> : <SunIcon />}
    </button>
  );
}
