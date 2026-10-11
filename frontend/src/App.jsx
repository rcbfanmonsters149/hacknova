import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import InspectorPage from './pages/InspectorPage';
import AuthorityPortalPage from './pages/AuthorityPortalPage';
import AttackLabPage from './pages/AttackLabPage';
import PoliciesPage from './pages/PoliciesPage';
import EvaluationPage from './pages/EvaluationPage';
import HistoryPage from './pages/HistoryPage';
import { api } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState('inspector');
  const [backendStatus, setBackendStatus] = useState('connecting');

  // Verify backend connectivity
  useEffect(() => {
    let isMounted = true;
    const checkServer = async () => {
      try {
        const res = await api.checkHealth();
        if (isMounted && res.status === 'healthy') {
          setBackendStatus('online');
        }
      } catch (e) {
        if (isMounted) setBackendStatus('offline');
      }
    };

    checkServer();
    const interval = setInterval(checkServer, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getPageInfo = () => {
    switch (activeTab) {
      case 'inspector':
        return {
          title: 'Inspect content',
          subtitle: 'Check what enters your AI application and understand how it is handled.',
        };
      case 'authority':
        return {
          title: 'Authority Investigation Portal',
          subtitle: 'Enterprise-wide employee prompt monitoring, forensic investigation, and escalated incident triage.',
        };
      case 'attack-lab':
        return {
          title: 'Explore attacks',
          subtitle: 'See how malicious instructions attempt to influence AI behavior.',
        };
      case 'policies':
        return {
          title: 'Security policies',
          subtitle: 'Control how suspicious content is handled.',
        };
      case 'evaluation':
        return {
          title: 'Evaluate performance',
          subtitle: 'Measure detections, false positives, and missed attacks.',
        };
      case 'history':
        return {
          title: 'Inspection history',
          subtitle: 'Searchable audit trail of past gateway inspections and actions.',
        };
      default:
        return { title: 'PromptShield X', subtitle: '' };
    }
  };

  const { title, subtitle } = getPageInfo();

  return (
    <div className="min-h-screen bg-[#F8F9FB] flex">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        backendStatus={backendStatus}
      />

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0">
        <Header title={title} subtitle={subtitle} />
        <div className="flex-1 pb-12">
          {activeTab === 'inspector' && <InspectorPage />}
          {activeTab === 'authority' && <AuthorityPortalPage />}
          {activeTab === 'attack-lab' && <AttackLabPage />}
          {activeTab === 'policies' && <PoliciesPage />}
          {activeTab === 'evaluation' && <EvaluationPage />}
          {activeTab === 'history' && <HistoryPage />}
        </div>
      </main>
    </div>
  );
}
