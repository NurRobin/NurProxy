import { Routes, Route, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import Agents from '../pages/Agents';
import Servers from '../pages/Servers';
import Domains from '../pages/Domains';
import Config from '../pages/Config';
import Settings from '../pages/Settings';
import Help from '../pages/Help';

export function AppRoutes({ overview }: { overview: ReactNode }) {
  return (
    <Routes>
      <Route path="/" element={overview} />
      <Route path="/agents" element={<Agents />} />
      <Route path="/servers" element={<Servers />} />
      <Route path="/domains" element={<Domains />} />
      <Route path="/config" element={<Config />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/help" element={<Help />} />
      <Route path="/help/:slug" element={<Help />} />
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
