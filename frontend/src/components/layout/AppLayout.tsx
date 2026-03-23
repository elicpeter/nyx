import { useState, useCallback } from 'react';
import { Routes, Route } from 'react-router-dom';
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
            <Route path="/scans/compare/:left/:right" element={<ScanComparePage />} />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/rules/:id" element={<RulesPage />} />
            <Route path="/triage" element={<TriagePage />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="/explorer" element={<ExplorerPage />} />
            <Route path="/debug" element={<StubPage />} />
            <Route path="/debug/cfg" element={<StubPage />} />
            <Route path="/debug/ssa" element={<StubPage />} />
            <Route path="/debug/call-graph" element={<StubPage />} />
            <Route path="/debug/taint" element={<StubPage />} />
            <Route path="/settings" element={<StubPage />} />
          </Routes>
        </main>
      </div>
      <NewScanModal open={scanModalOpen} onClose={() => setScanModalOpen(false)} />
    </div>
  );
}
