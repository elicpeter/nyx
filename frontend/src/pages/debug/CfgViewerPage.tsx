import { useDebugCfg } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import { CfgGraphCanvas } from '../../graph/components/CfgGraphCanvas';

interface CfgAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function CfgAnalysisPanel({
  file,
  functionName,
}: CfgAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugCfg(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading CFG..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="CFG data is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load CFG." />;
  }
  if (!data || data.nodes.length === 0) {
    return (
      <EmptyState message="No CFG nodes are available for this function." />
    );
  }

  return <CfgGraphCanvas data={data} />;
}
