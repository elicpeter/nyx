import { useEffect } from 'react';

const APP_NAME = 'Nyx';

/**
 * Sets `document.title` to `<page> · Nyx`. Restores the previous title on
 * unmount so transient pages (e.g. modals that re-render the page) don't
 * leave the title stuck.
 */
export function usePageTitle(title: string | null | undefined) {
  useEffect(() => {
    if (!title) return;
    const prev = document.title;
    document.title = `${title} · ${APP_NAME}`;
    return () => {
      document.title = prev;
    };
  }, [title]);
}
