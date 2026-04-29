import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

const CHORD_TIMEOUT_MS = 800;

const ROUTES: Record<string, string> = {
  o: '/',
  f: '/findings',
  s: '/scans',
  r: '/rules',
  t: '/triage',
  c: '/config',
  e: '/explorer',
  d: '/debug',
};

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (target.isContentEditable) return true;
  return false;
}

/**
 * Vim-style "g then X" navigation: press `g`, then within 800ms press a
 * letter to jump to that section. Cancels if the user types in an input.
 */
export function useChordNavigation() {
  const navigate = useNavigate();
  const armed = useRef<number | null>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (isTypingTarget(event.target)) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;

      if (armed.current !== null) {
        const route = ROUTES[event.key.toLowerCase()];
        window.clearTimeout(armed.current);
        armed.current = null;
        if (route) {
          event.preventDefault();
          navigate(route);
        }
        return;
      }

      if (event.key === 'g') {
        event.preventDefault();
        armed.current = window.setTimeout(() => {
          armed.current = null;
        }, CHORD_TIMEOUT_MS);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      if (armed.current !== null) window.clearTimeout(armed.current);
    };
  }, [navigate]);
}
