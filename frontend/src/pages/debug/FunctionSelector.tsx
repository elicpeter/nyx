import { useDebugFunctions } from '../../api/queries/debug';
import type { FunctionInfo } from '../../api/types';

interface Props {
  file: string;
  selectedFunction: string | null;
  onFunctionChange: (fn_name: string | null) => void;
  showFilePath?: boolean;
}

export function FunctionSelector({
  file,
  selectedFunction,
  onFunctionChange,
  showFilePath = true,
}: Props) {
  const { data: functions, isLoading } = useDebugFunctions(file || null);

  return (
    <div className="function-selector">
      {showFilePath && (
        <div className="function-selector-path">
          <span className="function-selector-path-label">File:</span>
          <code className="function-selector-path-value">
            {file || 'No file selected'}
          </code>
        </div>
      )}
      <div className="function-selector-field">
        <label>Function</label>
        <select
          value={selectedFunction ?? ''}
          onChange={(e) => onFunctionChange(e.target.value || null)}
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
              {fn.source_caps.length > 0 &&
                ` [src: ${fn.source_caps.join(',')}]`}
              {fn.sink_caps.length > 0 && ` [sink: ${fn.sink_caps.join(',')}]`}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
