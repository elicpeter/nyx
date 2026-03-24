import { useState, useEffect, useRef } from 'react';
import { useDebugFunctions } from '../../api/queries/debug';
import type { FunctionInfo } from '../../api/types';

interface Props {
  file: string;
  selectedFunction: string | null;
  onFileChange: (file: string) => void;
  onFunctionChange: (fn_name: string | null) => void;
}

const DEBOUNCE_MS = 400;

export function FunctionSelector({
  file,
  selectedFunction,
  onFileChange,
  onFunctionChange,
}: Props) {
  // Local input state for responsive typing; debounced sync to URL params.
  const [localFile, setLocalFile] = useState(file);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  // Sync external changes (e.g. back/forward navigation) into local state.
  useEffect(() => {
    setLocalFile(file);
  }, [file]);

  const handleFileChange = (value: string) => {
    setLocalFile(value);
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      onFileChange(value);
    }, DEBOUNCE_MS);
  };

  // Clean up timer on unmount.
  useEffect(() => () => clearTimeout(timerRef.current), []);

  // Query uses the debounced (URL-committed) file value, not the local input.
  const { data: functions, isLoading, error } = useDebugFunctions(file || null);

  return (
    <div className="function-selector">
      <div className="function-selector-field">
        <label>File</label>
        <input
          type="text"
          value={localFile}
          onChange={(e) => handleFileChange(e.target.value)}
          placeholder="path/to/file.js"
          className="function-selector-input"
        />
        {error && file && (
          <span className="function-selector-error">File not found</span>
        )}
      </div>
      <div className="function-selector-field">
        <label>Function</label>
        <select
          value={selectedFunction ?? ''}
          onChange={(e) =>
            onFunctionChange(e.target.value || null)
          }
          disabled={!functions || functions.length === 0}
          className="function-selector-select"
        >
          <option value="">
            {isLoading
              ? 'Loading...'
              : !functions || functions.length === 0
                ? 'No functions found'
                : 'Select function'}
          </option>
          {functions?.map((fn: FunctionInfo) => (
            <option key={fn.name} value={fn.name}>
              {fn.name}({fn.param_count} params) — L{fn.line}
              {fn.source_caps.length > 0 && ` [src: ${fn.source_caps.join(',')}]`}
              {fn.sink_caps.length > 0 && ` [sink: ${fn.sink_caps.join(',')}]`}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
