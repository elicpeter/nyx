import { FolderIcon } from '../icons/Icons';
import type { TreeEntry } from '../../api/types';

interface FileTreeProps {
  entries: TreeEntry[];
  expandedPaths: Set<string>;
  selectedPath: string | null;
  onToggleExpand: (path: string) => void;
  onSelectFile: (path: string) => void;
  loadedChildren: Map<string, TreeEntry[]>;
}

export function FileTree({
  entries,
  expandedPaths,
  selectedPath,
  onToggleExpand,
  onSelectFile,
  loadedChildren,
}: FileTreeProps) {
  return (
    <div className="file-tree">
      {entries.map((entry) => (
        <FileTreeNode
          key={entry.path}
          entry={entry}
          depth={0}
          expandedPaths={expandedPaths}
          selectedPath={selectedPath}
          onToggleExpand={onToggleExpand}
          onSelectFile={onSelectFile}
          loadedChildren={loadedChildren}
        />
      ))}
    </div>
  );
}

interface FileTreeNodeProps {
  entry: TreeEntry;
  depth: number;
  expandedPaths: Set<string>;
  selectedPath: string | null;
  onToggleExpand: (path: string) => void;
  onSelectFile: (path: string) => void;
  loadedChildren: Map<string, TreeEntry[]>;
}

function FileTreeNode({
  entry,
  depth,
  expandedPaths,
  selectedPath,
  onToggleExpand,
  onSelectFile,
  loadedChildren,
}: FileTreeNodeProps) {
  const isDir = entry.entry_type === 'dir';
  const isExpanded = expandedPaths.has(entry.path);
  const isSelected = selectedPath === entry.path;
  const children = loadedChildren.get(entry.path);

  const sevClass = entry.finding_count > 0 && entry.severity_max
    ? ` sev-${entry.severity_max.toLowerCase()}`
    : '';

  const handleClick = () => {
    if (isDir) {
      onToggleExpand(entry.path);
    } else {
      onSelectFile(entry.path);
    }
  };

  return (
    <>
      <div
        className={`tree-node${isSelected ? ' selected' : ''}${sevClass}`}
        style={{ paddingLeft: 8 + depth * 16 }}
        onClick={handleClick}
      >
        <span className={`tree-chevron${isDir ? '' : ' invisible'}`}>
          {isDir ? (isExpanded ? '▾' : '▸') : ''}
        </span>
        <span className="tree-node-icon">
          {isDir ? (
            <FolderIcon size={14} />
          ) : (
            <FileIcon language={entry.language} />
          )}
        </span>
        <span className="tree-node-name" title={entry.path}>
          {entry.name}
        </span>
        {entry.finding_count > 0 && (
          <span className="tree-node-badge">{entry.finding_count}</span>
        )}
      </div>
      {isDir && isExpanded && children && (
        <div className="tree-children">
          {children.map((child) => (
            <FileTreeNode
              key={child.path}
              entry={child}
              depth={depth + 1}
              expandedPaths={expandedPaths}
              selectedPath={selectedPath}
              onToggleExpand={onToggleExpand}
              onSelectFile={onSelectFile}
              loadedChildren={loadedChildren}
            />
          ))}
        </div>
      )}
    </>
  );
}

function FileIcon({ language }: { language?: string }) {
  const label = (language || '').charAt(0).toUpperCase() || '·';
  const color = langColor(language);
  return (
    <span className="file-icon" style={{ color }} title={language || 'file'}>
      {label}
    </span>
  );
}

function langColor(lang?: string): string {
  switch (lang?.toLowerCase()) {
    case 'javascript':
      return '#f0db4f';
    case 'typescript':
      return '#3178c6';
    case 'python':
      return '#3572a5';
    case 'rust':
      return '#dea584';
    case 'go':
      return '#00add8';
    case 'java':
      return '#b07219';
    case 'ruby':
      return '#cc342d';
    case 'php':
      return '#4f5d95';
    case 'c':
      return '#555555';
    case 'c++':
      return '#f34b7d';
    default:
      return 'var(--text-tertiary)';
  }
}
