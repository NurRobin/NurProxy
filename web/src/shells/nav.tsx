import type { ReactNode } from 'react';
import { LayoutDashboard, Server, HardDrive, Globe, Settings } from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

const cls = 'h-5 w-5';

// `label` is an i18n key (see locales nav.*); shells render it via t().
export const NAV: NavItem[] = [
  { to: '/', label: 'nav.overview', icon: <LayoutDashboard className={cls} /> },
  { to: '/agents', label: 'nav.agents', icon: <Server className={cls} /> },
  { to: '/servers', label: 'nav.servers', icon: <HardDrive className={cls} /> },
  { to: '/domains', label: 'nav.domains', icon: <Globe className={cls} /> },
  { to: '/settings', label: 'nav.settings', icon: <Settings className={cls} /> },
];
