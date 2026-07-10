import { useEffect, useState } from "react";

// ── Types ──

interface AuditEvent {
  id: string;
  session_id: string;
  agent_id: string;
  agent_type: string | null;
  step_number: number;
  tool_name: string;
  signature: string;
  policy_decision: string | null;
  created_at: string;
}

interface PolicyDecision {
  allowed: boolean;
  denials: string[];
}

interface PolicyVersion {
  hash: string;
  author: string;
  message: string;
  timestamp: string;
  changed_files: string[];
}

interface DiffHunk {
  header: string;
  lines: string[];
}

interface DiffFile {
  file: string;
  old_file: string;
  status: string;
  hunks: DiffHunk[];
}

// ── Helpers ──

function parseDecision(raw: string | null): PolicyDecision | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ── Components ──

function StatCard({
  label,
  value,
  alert,
}: {
  label: string;
  value: number;
  alert?: boolean;
}) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
      <div className="text-xs text-gray-500 uppercase tracking-wide">{label}</div>
      <div
        className={`text-2xl font-bold mt-1 ${alert ? "text-red-400" : "text-gray-100"}`}
      >
        {value}
      </div>
    </div>
  );
}

function TabBar({
  tabs,
  active,
  onChange,
}: {
  tabs: string[];
  active: string;
  onChange: (tab: string) => void;
}) {
  return (
    <div className="flex gap-1 border-b border-gray-800 mb-6">
      {tabs.map((tab) => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            active === tab
              ? "border-purple-400 text-purple-400"
              : "border-transparent text-gray-500 hover:text-gray-300"
          }`}
        >
          {tab}
        </button>
      ))}
    </div>
  );
}

// ── Audit Events Tab ──

function AuditTab() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEvents = async () => {
    try {
      const res = await fetch("/api/audit/events?limit=50");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setEvents(data.events || []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch events");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 10_000);
    return () => clearInterval(interval);
  }, []);

  const total = events.length;
  const allowed = events.filter((e) => {
    const d = parseDecision(e.policy_decision);
    return !d || d.allowed;
  }).length;
  const denied = total - allowed;
  const uniqueSessions = new Set(events.map((e) => e.session_id)).size;
  const uniqueAgents = new Set(events.map((e) => e.agent_id)).size;

  const toolCounts: Record<string, number> = {};
  events.forEach((e) => {
    toolCounts[e.tool_name] = (toolCounts[e.tool_name] || 0) + 1;
  });

  return (
    <div className="space-y-6">
      {!loading && !error && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Events" value={total} />
          <StatCard label="Sessions" value={uniqueSessions} />
          <StatCard label="Agents" value={uniqueAgents} />
          <StatCard label="Policy Denials" value={denied} alert={denied > 0} />
        </div>
      )}

      {total > 0 && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <h2 className="text-sm font-semibold text-gray-400 mb-2">
            Policy Decisions
          </h2>
          <div className="flex h-3 rounded-full overflow-hidden bg-gray-800">
            <div
              className="bg-emerald-500 transition-all"
              style={{ width: `${(allowed / total) * 100}%` }}
            />
            <div
              className="bg-red-500 transition-all"
              style={{ width: `${(denied / total) * 100}%` }}
            />
          </div>
          <div className="flex justify-between mt-2 text-xs text-gray-500">
            <span>✅ {allowed} allowed ({(allowed / total) * 100}%)</span>
            <span>❌ {denied} denied ({(denied / total) * 100}%)</span>
          </div>
        </div>
      )}

      {Object.keys(toolCounts).length > 0 && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <h2 className="text-sm font-semibold text-gray-400 mb-3">
            Tool Usage
          </h2>
          <div className="space-y-2">
            {Object.entries(toolCounts)
              .sort((a, b) => b[1] - a[1])
              .map(([tool, count]) => (
                <div key={tool} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-gray-500 w-24 truncate">
                    {tool}
                  </span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-purple-500 rounded-full transition-all"
                      style={{ width: `${(count / total) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-8 text-right">
                    {count}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}

      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-400">Audit Events</h2>
        </div>
        {loading ? (
          <div className="p-8 text-center text-gray-500">Loading events...</div>
        ) : error ? (
          <div className="p-8 text-center text-red-400">
            Error: {error}
            <button
              onClick={fetchEvents}
              className="ml-2 underline hover:text-red-300"
            >
              Retry
            </button>
          </div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No audit events yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase">
                  <th className="px-4 py-2">Time</th>
                  <th className="px-4 py-2">Session</th>
                  <th className="px-4 py-2">Agent</th>
                  <th className="px-4 py-2">Tool</th>
                  <th className="px-4 py-2">Policy</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const dec = parseDecision(e.policy_decision);
                  return (
                    <tr
                      key={e.id}
                      className="border-b border-gray-800/50 hover:bg-gray-800/30"
                    >
                      <td className="px-4 py-2 font-mono text-xs text-gray-500">
                        {new Date(e.created_at).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-gray-400 max-w-32 truncate">
                        {e.session_id}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-400">
                        {e.agent_id}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs">
                        {e.tool_name}
                      </td>
                      <td className="px-4 py-2">
                        {dec ? (
                          dec.allowed ? (
                            <span className="text-xs text-emerald-400">
                              ✅ allowed
                            </span>
                          ) : (
                            <span className="text-xs text-red-400">
                              ❌ {dec.denials.join(", ")}
                            </span>
                          )
                        ) : (
                          <span className="text-xs text-gray-600">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Policies Tab ──

const POLICY_API = "http://localhost:9003";

function PoliciesTab() {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [selected, setSelected] = useState<[string, string] | null>(null);
  const [diff, setDiff] = useState<DiffFile[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchVersions = async () => {
    try {
      const res = await fetch(`${POLICY_API}/api/policies/versions`);
      const data = await res.json();
      setVersions(data);
    } catch {
      setVersions([]);
    }
  };

  useEffect(() => {
    fetchVersions();
  }, []);

  const showDiff = async (oldHash: string, newHash: string) => {
    setSelected([oldHash, newHash]);
    setLoading(true);
    try {
      const res = await fetch(
        `${POLICY_API}/api/policies/diff?old=${oldHash}&new=${newHash}`
      );
      const data = await res.json();
      setDiff(data);
    } catch {
      setDiff([]);
    } finally {
      setLoading(false);
    }
  };

  const rollback = async (hash: string, message: string) => {
    if (!confirm(`Rollback to "${message}" (${hash})?`)) return;
    try {
      const res = await fetch(`${POLICY_API}/api/policies/rollback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash }),
      });
      const data = await res.json();
      if (data.success) {
        fetchVersions();
        setDiff([]);
        setSelected(null);
      }
    } catch {
      alert("Rollback failed");
    }
  };

  return (
    <div className="space-y-6">
      {/* Version list */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-gray-400">
            Policy Version History
          </h2>
          <button
            onClick={fetchVersions}
            className="px-3 py-1 text-xs bg-gray-800 hover:bg-gray-700 rounded"
          >
            Refresh
          </button>
        </div>
        {versions.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No versions found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase">
                  <th className="px-4 py-2">Hash</th>
                  <th className="px-4 py-2">Author</th>
                  <th className="px-4 py-2">Message</th>
                  <th className="px-4 py-2">Files</th>
                  <th className="px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {versions.map((v, i) => (
                  <tr
                    key={v.hash}
                    className="border-b border-gray-800/50 hover:bg-gray-800/30"
                  >
                    <td className="px-4 py-2 font-mono text-xs text-purple-400">
                      {v.hash}
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-400">
                      {v.author}
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-300">
                      {v.message}
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-500">
                      {v.changed_files.join(", ")}
                    </td>
                    <td className="px-4 py-2 flex gap-2">
                      {i > 0 && (
                        <button
                          onClick={() =>
                            showDiff(versions[i].hash, versions[i - 1].hash)
                          }
                          className="px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 rounded text-gray-400"
                        >
                          Diff →
                        </button>
                      )}
                      <button
                        onClick={() => rollback(v.hash, v.message)}
                        className="px-2 py-1 text-xs bg-gray-800 hover:bg-amber-900 rounded text-amber-400"
                      >
                        Rollback
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Diff viewer */}
      {selected && (
        <div className="bg-gray-900 rounded-lg border border-gray-800">
          <div className="px-4 py-3 border-b border-gray-800 flex justify-between items-center">
            <h2 className="text-sm font-semibold text-gray-400">
              Diff: {selected[0]} → {selected[1]}
            </h2>
            <button
              onClick={() => {
                setSelected(null);
                setDiff([]);
              }}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Close
            </button>
          </div>
          {loading ? (
            <div className="p-8 text-center text-gray-500">Loading diff...</div>
          ) : diff.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No changes</div>
          ) : (
            <div className="p-4 space-y-4">
              {diff.map((file) => (
                <div key={file.file}>
                  <div className="text-xs font-mono text-gray-500 mb-2">
                    {file.old_file} → {file.file}
                  </div>
                  <div className="bg-gray-950 rounded font-mono text-xs overflow-x-auto">
                    {file.hunks.map((hunk, hi) => (
                      <div key={hi}>
                        <div className="text-cyan-400 px-3 py-1 bg-gray-900/50">
                          {hunk.header}
                        </div>
                        {hunk.lines.map((line, li) => (
                          <div
                            key={li}
                            className={`px-3 py-0.5 ${
                              line.startsWith("+")
                                ? "bg-emerald-900/30 text-emerald-400"
                                : line.startsWith("-")
                                ? "bg-red-900/30 text-red-400"
                                : "text-gray-400"
                            }`}
                          >
                            {line}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── App ──

export default function App() {
  const [tab, setTab] = useState("Audit");

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="max-w-6xl mx-auto">
          <h1 className="text-xl font-bold tracking-tight">
            Tracepath{" "}
            <span className="text-purple-400">Compliance Dashboard</span>
          </h1>
          <p className="text-sm text-gray-500">Audit trail & policy management</p>
        </div>
      </header>

      <main className="max-w-6xl mx-auto p-6">
        <TabBar
          tabs={["Audit", "Policies"]}
          active={tab}
          onChange={setTab}
        />
        {tab === "Audit" ? <AuditTab /> : <PoliciesTab />}
      </main>
    </div>
  );
}
