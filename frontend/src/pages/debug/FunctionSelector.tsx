import { useDebugFunctions } from '../../api/queries/debug';
import type { FunctionInfo } from '../../api/types';

interface Props {
  file: string;
  selectedFunction: string | null;
  onFileChange: (file: string) => void;
  onFunctionChange: (fn_name: string | null) => void;
}

export function FunctionSelector({
  file,
  selectedFunction,
  onFileChange,
  onFunctionChange,
}: Props) {
  const { data: functions, isLoading } = useDebugFunctions(file || null);

  return (
    <div className="function-selector">
      <div className="function-selector-field">
        <label>File</label>
        <input
          type="text"
          value={file}
          onChange={(e) => {
            onFileChange(e.target.value);
            onFunctionChange(null);
          }}
          placeholder="path/to/file.js"
          className="function-selector-input"
        />
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
