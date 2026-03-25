import { useState, useCallback } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { HeaderBar } from './HeaderBar';
import { NewScanModal } from '../../modals/NewScanModal';
import { OverviewPage } from '../../pages/OverviewPage';
import { FindingsPage } from '../../pages/FindingsPage';
import { FindingDetailPage } from '../../pages/FindingDetailPage';
import { ScansPage } from '../../pages/ScansPage';
import { ScanDetailPage } from '../../pages/ScanDetailPage';
import { ScanComparePage } from '../../pages/ScanComparePage';
import { RulesPage } from '../../pages/RulesPage';
import { TriagePage } from '../../pages/TriagePage';
import { ConfigPage } from '../../pages/ConfigPage';
import { StubPage } from '../../pages/StubPage';
import { ExplorerPage } from '../../pages/ExplorerPage';
import { DebugLayout } from '../../pages/debug/DebugLayout';
import { CallGraphPage } from '../../pages/debug/CallGraphPage';
import { SummaryExplorerPage } from '../../pages/debug/SummaryExplorerPage';

export function AppLayout() {
  const [scanModalOpen, setScanModalOpen] = useState(false);

  const handleStartScan = useCallback(() => {
    setScanModalOpen(true);
  }, []);

  return (
    <div id="app">
      <Sidebar />
      <div className="main-panel">
        <HeaderBar onStartScan={handleStartScan} />
        <main className="content">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route
              path="/scans/compare/:left/:right"
              element={<ScanComparePage />}
            />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/rules/:id" element={<RulesPage />} />
            <Route path="/triage" element={<TriagePage />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="/explorer" element={<ExplorerPage />} />
            <Route path="/debug" element={<DebugLayout />}>
              <Route
                index
                element={<Navigate to="/debug/call-graph" replace />}
              />
              <Route path="call-graph" element={<CallGraphPage />} />
              <Route path="summaries" element={<SummaryExplorerPage />} />
            </Route>
            <Route path="/settings" element={<StubPage />} />
          </Routes>
        </main>
      </div>
      <NewScanModal
        open={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
      />
    </div>
  );
}
