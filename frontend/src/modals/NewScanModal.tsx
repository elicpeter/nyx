import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Modal } from '../components/ui/Modal';
import { useHealth } from '../api/queries/health';
import { useStartScan } from '../api/mutations/scans';

interface NewScanModalProps {
  open: boolean;
  onClose: () => void;
}

export function NewScanModal({ open, onClose }: NewScanModalProps) {
  const { data: health } = useHealth();
  const startScan = useStartScan();
  const navigate = useNavigate();
  const defaultRoot = health?.scan_root || '';
  const [scanRoot, setScanRoot] = useState('');

  const handleStart = async () => {
    const root = scanRoot.trim();
    const body = root && root !== defaultRoot ? { scan_root: root } : undefined;
    try {
      await startScan.mutateAsync(body);
      onClose();
      navigate('/scans');
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to start scan');
    }
  };

  if (!open) return null;

  return (
    <Modal open={open} onClose={onClose} className="scan-modal-overlay">
      <div className="scan-modal">
        <h3>Start New Scan</h3>
        <div className="scan-modal-form">
          <div className="form-group">
            <label>Scan Root</label>
            <input
              type="text"
              value={scanRoot || defaultRoot}
              onChange={(e) => setScanRoot(e.target.value)}
              placeholder="/path/to/project"
            />
          </div>
          <div className="scan-modal-actions">
            <button className="btn btn-sm" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleStart}
              disabled={startScan.isPending}
            >
              {startScan.isPending ? 'Starting...' : 'Start Scan'}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
