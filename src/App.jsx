import React, { useState, useEffect } from 'react';
import { Topbar } from './components/Topbar.jsx';
import { SetupWizard } from './components/SetupWizard.jsx';
import { CertExplorer } from './components/CertExplorer.jsx';
import { CsrStudio } from './components/CsrStudio.jsx';
import { OpaManager } from './components/OpaManager.jsx';
import { AuditLogViewer } from './components/AuditLogViewer.jsx';
import { ApiExplorer } from './components/ApiExplorer.jsx';

export function App() {
  const [activeTab, setActiveTab] = useState('explorer');
  const [caStatus, setCaStatus] = useState(null);
  const [showWizard, setShowWizard] = useState(false);

  const fetchCaStatus = async () => {
    try {
      const res = await fetch('/api/setup/status');
      const data = await res.json();
      if (res.ok) {
        setCaStatus(data);
        if (!data.initialized) {
          setShowWizard(true);
        }
      }
    } catch (err) {
      console.error('Error fetching CA status:', err);
    }
  };

  useEffect(() => {
    fetchCaStatus();
  }, []);

  const handleWizardComplete = (newConfig) => {
    setShowWizard(false);
    fetchCaStatus();
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Topbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        caStatus={caStatus}
        onRefreshStatus={fetchCaStatus}
        onOpenResetWizard={() => setShowWizard(true)}
      />

      <main className="container" style={{ flex: 1, padding: '1.5rem 1.5rem 3rem' }}>
        {activeTab === 'explorer' && (
          <CertExplorer
            caStatus={caStatus}
            onRequestNewCert={() => setActiveTab('csr')}
          />
        )}

        {activeTab === 'csr' && (
          <CsrStudio
            caStatus={caStatus}
            onCertIssued={() => setActiveTab('explorer')}
          />
        )}

        {activeTab === 'opa' && <OpaManager />}

        {activeTab === 'audit' && <AuditLogViewer />}

        {activeTab === 'api' && <ApiExplorer />}
      </main>

      {/* Setup Wizard Modal */}
      {showWizard && (
        <SetupWizard
          onComplete={handleWizardComplete}
          onClose={caStatus?.initialized ? () => setShowWizard(false) : null}
        />
      )}
    </div>
  );
}

export default App;
