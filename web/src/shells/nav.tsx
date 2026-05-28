import type { ReactNode } from 'react';
import { LayoutDashboard, Server, HardDrive, Globe, Settings } from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

const cls = 'h-5 w-5';

export const NAV: NavItem[] = [
  { to: '/', label: 'Overview', icon: <LayoutDashboard className={cls} /> },
  { to: '/agents', label: 'Agents', icon: <Server className={cls} /> },
  { to: '/servers', label: 'Servers', icon: <HardDrive className={cls} /> },
  { to: '/domains', label: 'Domains', icon: <Globe className={cls} /> },
  { to: '/settings', label: 'Settings', icon: <Settings className={cls} /> },
];
