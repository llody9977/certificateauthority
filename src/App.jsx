import React, { useState, useEffect } from 'react';
import { Topbar } from './components/Topbar.jsx';
import { SetupWizard } from './components/SetupWizard.jsx';
import { CertExplorer } from './components/CertExplorer.jsx';
import { CsrStudio } from './components/CsrStudio.jsx';
import { OpaManager } from './components/OpaManager.jsx';
import { AuditLogViewer } from './components/AuditLogViewer.jsx';
import { ApiExplorer } from './components/ApiExplorer.jsx';
import { AiAssistant } from './components/AiAssistant.jsx';
import { ExpirationRadar } from './components/ExpirationRadar.jsx';
import { BulkIssuance } from './components/BulkIssuance.jsx';

export function App() {
  const [activeTab, setActiveTab] = useState('explorer');
  const [caStatus, setCaStatus] = useState(null);
  const [showWizard, setShowWizard] = useState(false);
  const [currentUser, setCurrentUser] = useState({ role: 'Admin', performedBy: 'admin' });

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

  // Global Fetch Interceptor to automatically inject RBAC headers
  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async function () {
      let [resource, config] = arguments;
      if (typeof resource === 'string' && resource.startsWith('/api/')) {
        config = config || {};
        config.headers = {
          'X-User-Role': currentUser.role,
          'X-User-Name': currentUser.performedBy,
          ...config.headers
        };
      }
      return originalFetch.apply(this, [resource, config]);
    };

    return () => {
      window.fetch = originalFetch;
    };
  }, [currentUser]);

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
        currentUser={currentUser}
        onRoleChange={(newRole) => setCurrentUser(prev => ({ ...prev, role: newRole }))}
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

        {activeTab === 'radar' && <ExpirationRadar />}

        {activeTab === 'bulk' && <BulkIssuance onComplete={fetchCaStatus} />}

        {activeTab === 'assistant' && (
          <AiAssistant
            caStatus={caStatus}
            currentUser={currentUser}
            onRefreshStatus={fetchCaStatus}
          />
        )}

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
