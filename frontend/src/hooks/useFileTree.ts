import { useState, useEffect, useCallback } from 'react';
import { useExplorerTree } from '../api/queries/explorer';
import type { TreeEntry } from '../api/types';

export interface UseFileTreeReturn {
  rootEntries: TreeEntry[] | undefined;
  isLoading: boolean;
  expandedPaths: Set<string>;
  loadedChildren: Map<string, TreeEntry[]>;
  selectedPath: string | null;
  handleToggleExpand: (path: string) => void;
  handleSelectFile: (path: string) => void;
  setSelectedPath: (path: string | null) => void;
}

export function useFileTree(
  initialPath?: string | null,
  onSelectFile?: (path: string) => void,
): UseFileTreeReturn {
  const [selectedPath, setSelectedPath] = useState<string | null>(
    initialPath ?? null,
  );
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [loadedChildren, setLoadedChildren] = useState<
    Map<string, TreeEntry[]>
  >(new Map());
  const [expandQueue, setExpandQueue] = useState<string | null>(null);

  const { data: rootEntries, isLoading } = useExplorerTree();
  const { data: childEntries } = useExplorerTree(expandQueue || undefined);

  // Sync external path changes (e.g. back/forward navigation).
  useEffect(() => {
    const normalized = initialPath ?? null;
    setSelectedPath((prev) => (prev !== normalized ? normalized : prev));
  }, [initialPath]);

  // Auto-expand ancestor directories for deep-linked files so the selected
  // file is visible in the tree once its parent directories load.
  useEffect(() => {
    if (!initialPath) {
      return;
    }

    const ancestors = getAncestorPaths(initialPath);
    if (ancestors.length === 0) {
      return;
    }

    setExpandedPaths((prev) => {
      const next = new Set(prev);
      let changed = false;
      for (const ancestor of ancestors) {
        if (!next.has(ancestor)) {
          next.add(ancestor);
          changed = true;
        }
      }
      return changed ? next : prev;
    });

    const nextToLoad = ancestors.find(
      (ancestor) => !loadedChildren.has(ancestor),
    );
    if (nextToLoad && expandQueue !== nextToLoad) {
      setExpandQueue(nextToLoad);
    }
  }, [expandQueue, initialPath, loadedChildren]);

  // Store child entries when they arrive for an expanded directory.
  useEffect(() => {
    if (expandQueue && childEntries) {
      setLoadedChildren((prev) => {
        const next = new Map(prev);
        next.set(expandQueue, childEntries);
        return next;
      });
      setExpandQueue(null);
    }
  }, [expandQueue, childEntries]);

  const handleToggleExpand = useCallback(
    (path: string) => {
      setExpandedPaths((prev) => {
        const next = new Set(prev);
        if (next.has(path)) {
          next.delete(path);
        } else {
          next.add(path);
          if (!loadedChildren.has(path)) {
            setExpandQueue(path);
          }
        }
        return next;
      });
    },
    [loadedChildren],
  );

  const handleSelectFile = useCallback(
    (path: string) => {
      setSelectedPath(path);
      onSelectFile?.(path);
    },
    [onSelectFile],
  );

  return {
    rootEntries,
    isLoading,
    expandedPaths,
    loadedChildren,
    selectedPath,
    handleToggleExpand,
    handleSelectFile,
    setSelectedPath,
  };
}

function getAncestorPaths(path: string): string[] {
  const parts = path.split('/').filter(Boolean);
  const ancestors: string[] = [];

  for (let i = 1; i < parts.length; i += 1) {
    ancestors.push(parts.slice(0, i).join('/'));
  }

  return ancestors;
}
