import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Domain, AuditLogEntry } from '../lib/types';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';

function timeAgo(dateStr: string | undefined): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export default function Overview() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [a, d, log] = await Promise.all([
        api.listAgents(),
        api.listDomains(),
        api.getAuditLog({ limit: '20' }),
      ]);
      setAgents(a);
      setDomains(d);
      setAuditLog(log.entries ?? []);
    } catch {
      // silently fail on refresh
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const agentsByStatus = (s: string) => agents.filter((a) => a.status === s).length;
  const domainsByStatus = (s: string) => domains.filter((d) => d.status === s).length;

  if (loading) {
    return <div className="text-gray-400">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Overview</h1>
        <Link
          to="/domains"
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          New Domain
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Agents" value={agents.length} sub={`${agentsByStatus('adopted')} adopted, ${agentsByStatus('pending')} pending`} />
        <StatCard label="Domains" value={domains.length} sub={`${domainsByStatus('active')} active, ${domainsByStatus('pending')} pending`} />
        <StatCard label="Errors" value={agentsByStatus('error') + domainsByStatus('error')} sub="agents + domains" alert={agentsByStatus('error') + domainsByStatus('error') > 0} />
        <StatCard label="Offline" value={agentsByStatus('offline')} sub="agents" />
      </div>

      {/* Agents */}
      {agents.length === 0 ? (
        <EmptyState
          title="No agents connected"
          description="Install an agent to get started. Agents register themselves and appear here for adoption."
          action={
            <Link to="/agents" className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
              Go to Agents
            </Link>
          }
        />
      ) : (
        <div>
          <h2 className="mb-3 text-lg font-semibold text-white">Agents</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {agents.map((agent) => {
              const agentDomains = domains.filter((d) => {
                // match via servers would be ideal, but we don't have server->agent mapping on domain
                // so we just show overall count
                return d.status !== 'deleting';
              });
              return (
                <Link
                  key={agent.id}
                  to="/agents"
                  className="rounded-xl border border-gray-800 bg-gray-900 p-4 transition-colors hover:border-gray-700"
                >
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-white">{agent.name}</p>
                      <p className="truncate text-sm text-gray-400">{agent.fqdn}</p>
                    </div>
                    <StatusBadge status={agent.status} />
                  </div>
                  <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
                    {agent.public_ip && <span>IP: {agent.public_ip}</span>}
                    <span>Seen: {timeAgo(agent.last_seen)}</span>
                    {agent.version && <span>v{agent.version}</span>}
                  </div>
                  <div className="mt-2 text-xs text-gray-500">
                    {agentDomains.length} domain{agentDomains.length !== 1 ? 's' : ''}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      )}

      {/* Recent Activity */}
      {auditLog.length > 0 && (
        <div>
          <h2 className="mb-3 text-lg font-semibold text-white">Recent Activity</h2>
          <div className="rounded-xl border border-gray-800 bg-gray-900 divide-y divide-gray-800">
            {auditLog.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between px-4 py-3">
                <div className="min-w-0">
                  <p className="text-sm text-gray-200">
                    <span className="font-medium text-white">{entry.action}</span>
                    {' '}
                    <span className="text-gray-400">{entry.entity_type}</span>
                    {entry.details && (
                      <span className="text-gray-500"> — {entry.details}</span>
                    )}
                  </p>
                </div>
                <div className="ml-4 flex-shrink-0 text-xs text-gray-500">
                  {timeAgo(entry.created_at)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, sub, alert }: { label: string; value: number; sub: string; alert?: boolean }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <p className="text-sm text-gray-400">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${alert ? 'text-red-400' : 'text-white'}`}>{value}</p>
      <p className="mt-0.5 text-xs text-gray-500">{sub}</p>
    </div>
  );
}
