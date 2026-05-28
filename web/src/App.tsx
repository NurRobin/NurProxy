import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Overview from './pages/Overview';
import Agents from './pages/Agents';
import Domains from './pages/Domains';
import Settings from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100">
        <nav className="border-b border-gray-800 bg-gray-900">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex h-14 items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-white">NurProxy</span>
              </div>
              <div className="flex gap-1">
                {[
                  { to: '/', label: 'Overview' },
                  { to: '/agents', label: 'Agents' },
                  { to: '/domains', label: 'Domains' },
                  { to: '/settings', label: 'Settings' },
                ].map(({ to, label }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/'}
                    className={({ isActive }) =>
                      `rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                        isActive
                          ? 'bg-gray-800 text-white'
                          : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                      }`
                    }
                  >
                    {label}
                  </NavLink>
                ))}
              </div>
            </div>
          </div>
        </nav>
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/domains" element={<Domains />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
