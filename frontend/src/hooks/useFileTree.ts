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
  const [selectedPath, setSelectedPath] = useState<string | null>(initialPath ?? null);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [loadedChildren, setLoadedChildren] = useState<Map<string, TreeEntry[]>>(new Map());
  const [expandQueue, setExpandQueue] = useState<string | null>(null);

  const { data: rootEntries, isLoading } = useExplorerTree();
  const { data: childEntries } = useExplorerTree(expandQueue || undefined);

  // Sync external path changes (e.g. back/forward navigation).
  useEffect(() => {
    const normalized = initialPath ?? null;
    setSelectedPath((prev) => (prev !== normalized ? normalized : prev));
  }, [initialPath]);

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
