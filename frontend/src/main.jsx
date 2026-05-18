import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, Ban, Bell, CircleStop, Cpu, Download, FileSpreadsheet, FileText, GitBranch, Network, Play, Radar, Search, ShieldAlert, Upload, Wifi } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function App() {
  const [stats, setStats] = useState(null);
  const [packets, setPackets] = useState([]);
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [interfaces, setInterfaces] = useState([]);
  const [activeView, setActiveView] = useState('traffic');
  const [scanTarget, setScanTarget] = useState('127.0.0.1');
  const [captureInterface, setCaptureInterface] = useState('demo0');
  const [captureMode, setCaptureMode] = useState('demo');
  const [scanState, setScanState] = useState({ running: false, message: '' });
  const [pcapState, setPcapState] = useState('');
  const [aiState, setAiState] = useState({ running: false, text: '' });
  const [aiModel, setAiModel] = useState('llama3.2');
  const [deviceContext, setDeviceContext] = useState(null);

  async function refresh() {
    const [statsRes, packetsRes, devicesRes, alertsRes, statusRes, scansRes, topologyRes] = await Promise.all([
      fetch(`${API}/stats`),
      fetch(`${API}/packets/history?limit=80`),
      fetch(`${API}/devices`),
      fetch(`${API}/alerts?limit=20`),
      fetch(`${API}/capture/status`),
      fetch(`${API}/scan/history?limit=10`),
      fetch(`${API}/topology`),
      fetch(`${API}/interfaces`)
    ]);
    setStats(await statsRes.json());
    setPackets(await packetsRes.json());
    setDevices(await devicesRes.json());
    setAlerts(await alertsRes.json());
    setStatus(await statusRes.json());
    setScanHistory(await scansRes.json());
    setTopology(await topologyRes.json());
    setInterfaces(await interfacesRes.json());
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 1500);
    return () => clearInterval(id);
  }, []);

  const protocolData = useMemo(() => Object.entries(stats?.protocols || {}).map(([name, value]) => ({ name, value })), [stats]);
  const talkerData = useMemo(() => (stats?.top_talkers || []).map(([ip, packets]) => ({ ip, packets })), [stats]);

  async function startCapture() {
    await fetch(`${API}/capture/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ interface: captureInterface, mode: captureMode }) });
    refresh();
  }

  async function stopCapture() {
    await fetch(`${API}/capture/stop`, { method: 'POST' });
    refresh();
  }

  function exportEvidence() {
    window.open(`${API}/forensics/export`, '_blank');
  }

  function exportReport() {
    window.open(`${API}/forensics/report`, '_blank');
  }

  function openExport(path) {
    window.open(`${API}${path}`, '_blank');
  }

  async function runNmapScan(event) {
    event.preventDefault();
    setScanState({ running: true, message: `Scanning ${scanTarget}...` });
    try {
      const response = await fetch(`${API}/scan/nmap`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target: scanTarget, arguments: ['-T4', '-F'] })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || 'Nmap scan failed');
      setScanState({ running: false, message: `${payload.hosts.length} host(s), ${payload.new_hosts.length} new, ${payload.changed_hosts.length} changed, ${payload.alerts_created} alert(s)` });
      await refresh();
    } catch (error) {
      setScanState({ running: false, message: error.message });
    }
  }

  async function resolveAlert(alertId) {
    await fetch(`${API}/alerts/${alertId}/resolve`, { method: 'POST' });
    refresh();
  }

  async function blockAlert(alertId) {
    await fetch(`${API}/alerts/${alertId}/block?dry_run=true`, { method: 'POST' });
    refresh();
  }

  async function simulate(scenario) {
    await fetch(`${API}/simulate/${scenario}`, { method: 'POST' });
    refresh();
  }

  async function uploadPcap(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setPcapState(`Analyzing ${file.name}...`);
    const form = new FormData();
    form.append('file', file);
    const response = await fetch(`${API}/pcap/upload`, { method: 'POST', body: form });
    const payload = await response.json();
    setPcapState(response.ok ? `${payload.packets_imported} packets imported, ${payload.alerts} alerts total` : payload.detail);
    refresh();
  }

  async function runAiAnalysis() {
    setAiState({ running: true, text: 'Asking Ollama for analysis...' });
    try {
      const response = await fetch(`${API}/ai/analyze?model=${encodeURIComponent(aiModel)}`, { method: 'POST' });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || 'AI analysis failed');
      setAiState({ running: false, text: payload.analysis });
    } catch (error) {
      setAiState({ running: false, text: error.message });
    }
  }

  async function loadDeviceContext(deviceId) {
    const response = await fetch(`${API}/devices/${encodeURIComponent(deviceId)}/context`);
    setDeviceContext(await response.json());
  }

  const navItems = [
    ['traffic', Activity, 'Live Traffic'],
    ['devices', Network, 'Devices'],
    ['alerts', Bell, 'Alerts'],
    ['forensics', Wifi, 'Forensics']
  ];

  return (
    <main>
      <aside>
        <div className="brand"><ShieldAlert size={24} /> PROBE</div>
        <nav>
          {navItems.map(([id, Icon, label]) => (
            <button key={id} className={activeView === id ? 'active' : ''} onClick={() => setActiveView(id)}>
              <Icon size={18} /> {label}
            </button>
          ))}
        </nav>
      </aside>

      <section className="workspace">
        <header>
          <div>
            <p>CT-DFIR-03</p>
            <h1>Network Forensics Command Center</h1>
          </div>
          <div className="actions">
            <select value={`${captureMode}:${captureInterface}`} onChange={event => {
              const [mode, iface] = event.target.value.split(':');
              setCaptureMode(mode);
              setCaptureInterface(iface);
            }}>
              <option value="demo:demo0">demo0</option>
              {interfaces.filter(item => item.name !== 'demo0').map(item => <option key={item.name} value={`live:${item.name}`}>{item.name}</option>)}
            </select>
            <button title="Start capture" onClick={startCapture}><Play size={18} /> Start</button>
            <button title="Stop capture" onClick={stopCapture}><CircleStop size={18} /> Stop</button>
            <button title="Export evidence" onClick={exportEvidence}><Download size={18} /> Export</button>
          </div>
        </header>

        <section className="metrics">
          <Metric label="Packets" value={stats?.packets || 0} />
          <Metric label="Devices" value={stats?.devices || 0} />
          <Metric label="Alerts" value={stats?.alerts || 0} tone="alert" />
          <Metric label="High Risk" value={stats?.high_risk_devices || 0} tone="alert" />
        </section>

        {activeView === 'traffic' && <TrafficView protocolData={protocolData} talkerData={talkerData} packets={packets} simulate={simulate} uploadPcap={uploadPcap} pcapState={pcapState} />}
        {activeView === 'devices' && <DevicesView devices={devices} scanHistory={scanHistory} topology={topology} deviceContext={deviceContext} loadDeviceContext={loadDeviceContext} scanTarget={scanTarget} setScanTarget={setScanTarget} scanState={scanState} runNmapScan={runNmapScan} />}
        {activeView === 'alerts' && <AlertsView alerts={alerts} resolveAlert={resolveAlert} blockAlert={blockAlert} />}
        {activeView === 'forensics' && <ForensicsView stats={stats} packets={packets} alerts={alerts} scanHistory={scanHistory} exportEvidence={exportEvidence} exportReport={exportReport} openExport={openExport} aiModel={aiModel} setAiModel={setAiModel} runAiAnalysis={runAiAnalysis} aiState={aiState} />}
      </section>
    </main>
  );
}

function TrafficView({ protocolData, talkerData, packets, simulate, uploadPcap, pcapState }) {
  return (
    <>
      <section className="grid">
        <Panel title="PCAP Upload">
          <label className="file-picker">
            <Upload size={18} /> Analyze PCAP
            <input type="file" accept=".pcap,.pcapng" onChange={uploadPcap} />
          </label>
          <p className="muted">{pcapState || 'Upload Wireshark captures for offline forensic analysis.'}</p>
        </Panel>
        <Panel title="Attack Simulation">
          <div className="button-grid">
            <button onClick={() => simulate('port_scan')}>Port Scan</button>
            <button onClick={() => simulate('dns_tunnel')}>DNS Tunnel</button>
            <button onClick={() => simulate('arp_spoof')}>ARP Spoof</button>
            <button onClick={() => simulate('beaconing')}>Beaconing</button>
          </div>
        </Panel>
      </section>
      <section className="grid">
        <Panel title="Protocol Mix">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={protocolData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={82}>
                {protocolData.map((_, index) => <Cell key={index} fill={['#0f766e', '#2563eb', '#dc2626', '#9333ea', '#f59e0b'][index % 5]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="Top Talkers">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={talkerData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="ip" tick={{ fontSize: 11 }} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="packets" fill="#2563eb" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </section>
      <PacketTable packets={packets} />
    </>
  );
}

function DevicesView({ devices, scanHistory, topology, deviceContext, loadDeviceContext, scanTarget, setScanTarget, scanState, runNmapScan }) {
  return (
    <>
      <Panel title="Nmap Discovery">
        <form className="scan-form" onSubmit={runNmapScan}>
          <label>
            Target
            <input value={scanTarget} onChange={event => setScanTarget(event.target.value)} placeholder="127.0.0.1 or 192.168.1.0/24" />
          </label>
          <button disabled={scanState.running}><Search size={18} /> {scanState.running ? 'Scanning' : 'Run Scan'}</button>
          <span>{scanState.message}</span>
        </form>
      </Panel>
      <section className="grid">
        <Panel title="Network Topology">
          <TopologyGraph topology={topology} />
        </Panel>
        <Panel title="Scan History">
          <div className="scan-history">
            {scanHistory.map(scan => (
              <article key={scan.id}>
                <strong>{scan.target}</strong>
                <span>{new Date(scan.finished_at).toLocaleTimeString()} · {scan.hosts.length} host(s)</span>
                <p>{scan.new_hosts.length} new · {scan.changed_hosts.length} changed · {scan.alerts_created} alert(s)</p>
              </article>
            ))}
          </div>
        </Panel>
      </section>
      <Panel title="Device Explorer">
        <table>
          <thead><tr><th>Host</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Open Ports</th><th>Risk</th></tr></thead>
          <tbody>
            {devices.map(device => (
              <tr key={device.id}>
                <td><button className="link-button" onClick={() => loadDeviceContext(device.id)}>{device.hostname || 'unknown'}</button></td>
                <td>{device.ip_address}</td>
                <td>{device.mac_address || '-'}</td>
                <td>{device.vendor || '-'}</td>
                <td>{device.open_ports?.length ? device.open_ports.join(', ') : '-'}</td>
                <td><span className={device.risk_score > 80 ? 'risk high' : 'risk'}>{device.risk_score}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      {deviceContext && (
        <Panel title="Device Detail">
          <div className="detail-grid">
            <div><strong>{deviceContext.device.ip_address}</strong><span>{deviceContext.device.mac_address || 'No MAC observed'}</span></div>
            <div><strong>{deviceContext.device.risk_score}</strong><span>risk score</span></div>
            <div><strong>{deviceContext.alerts.length}</strong><span>related alerts</span></div>
            <div><strong>{deviceContext.packets.length}</strong><span>related packets</span></div>
          </div>
          <p className="muted">Open ports: {deviceContext.device.open_ports?.join(', ') || 'none observed'}</p>
        </Panel>
      )}
    </>
  );
}

function TopologyGraph({ topology }) {
  const nodes = topology.nodes || [];
  const edges = topology.edges || [];
  if (!nodes.length) return <div className="empty">Run an Nmap scan to populate the topology.</div>;
  return (
    <div className="topology">
      {nodes.slice(0, 24).map((node, index) => {
        const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2;
        const radius = node.type === 'scanner' ? 0 : 40;
        const x = 50 + Math.cos(angle) * radius;
        const y = 50 + Math.sin(angle) * radius;
        return (
          <div
            key={node.id}
            className={`topology-node ${node.risk >= 70 ? 'danger' : ''} ${node.type}`}
            style={{ left: `${x}%`, top: `${y}%` }}
            title={`${node.label} risk ${node.risk}`}
          >
            {node.label}
          </div>
        );
      })}
      <span className="edge-count"><GitBranch size={16} /> {edges.length} links</span>
    </div>
  );
}

function AlertsView({ alerts, resolveAlert, blockAlert }) {
  return (
    <Panel title="Active Threat Center">
      <div className="alerts page-list">
        {alerts.map(alert => (
          <article key={alert.id} className={`alert ${alert.severity}`}>
            <div className="alert-head">
              <strong>{alert.alert_type}</strong>
              <div className="actions inline">
                <button onClick={() => blockAlert(alert.id)}><Ban size={15} /> Block</button>
                <button onClick={() => resolveAlert(alert.id)}>Resolve</button>
              </div>
            </div>
            <span>{alert.severity} · score {alert.threat_score} · {alert.source_ip || 'unknown source'}</span>
            <p>{alert.description}</p>
          </article>
        ))}
      </div>
    </Panel>
  );
}

function ForensicsView({ stats, packets, alerts, scanHistory, exportEvidence, exportReport, openExport, aiModel, setAiModel, runAiAnalysis, aiState }) {
  return (
    <>
      <section className="grid">
        <Panel title="Evidence Summary">
          <div className="forensics-summary">
            <div><Radar size={20} /><strong>{stats?.packets || 0}</strong><span>packet records</span></div>
            <div><Bell size={20} /><strong>{stats?.alerts || 0}</strong><span>alert records</span></div>
            <div><Network size={20} /><strong>{stats?.devices || 0}</strong><span>device records</span></div>
          </div>
          <div className="actions inline">
            <button onClick={exportEvidence}><Download size={18} /> Export JSON</button>
            <button onClick={exportReport}><FileText size={18} /> Evidence Report</button>
            <button onClick={() => openExport('/forensics/report?format=html')}><FileText size={18} /> HTML</button>
            <button onClick={() => openExport('/forensics/report?format=pdf')}><FileText size={18} /> PDF</button>
          </div>
        </Panel>
        <Panel title="CSV Exports">
          <div className="button-grid">
            {['devices', 'alerts', 'packets', 'scans'].map(kind => <button key={kind} onClick={() => openExport(`/forensics/csv/${kind}`)}><FileSpreadsheet size={18} /> {kind}</button>)}
          </div>
          <button onClick={() => openExport('/forensics/hash')}><Cpu size={18} /> Evidence Hash</button>
        </Panel>
      </section>
      <section className="grid">
        <Panel title="AI Analysis">
          <div className="scan-form">
            <label>Ollama Model<input value={aiModel} onChange={event => setAiModel(event.target.value)} /></label>
            <button disabled={aiState.running} onClick={runAiAnalysis}><Cpu size={18} /> Analyze</button>
            <button onClick={() => openExport(`/ai/report.pdf?model=${encodeURIComponent(aiModel)}`)}><FileText size={18} /> AI PDF</button>
          </div>
          <pre className="ai-output">{aiState.text || 'Uses your Ollama server at port 11434 to summarize evidence and recommend next steps.'}</pre>
        </Panel>
        <Panel title="Incident Timeline">
          <div className="timeline">
            {alerts.slice(0, 8).map(alert => (
              <div key={alert.id}><time>{new Date(alert.timestamp).toLocaleTimeString()}</time><span>{alert.alert_type}</span></div>
            ))}
          </div>
        </Panel>
      </section>
      <Panel title="Recent Scan Diffs">
        <table>
          <thead><tr><th>Target</th><th>Finished</th><th>Hosts</th><th>New Hosts</th><th>Changed Hosts</th><th>Alerts</th></tr></thead>
          <tbody>
            {scanHistory.map(scan => (
              <tr key={scan.id}>
                <td>{scan.target}</td>
                <td>{new Date(scan.finished_at).toLocaleString()}</td>
                <td>{scan.hosts.length}</td>
                <td>{scan.new_hosts.join(', ') || '-'}</td>
                <td>{scan.changed_hosts.join(', ') || '-'}</td>
                <td>{scan.alerts_created}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <PacketTable packets={packets} />
    </>
  );
}

function PacketTable({ packets }) {
  return (
    <Panel title="Packet Explorer">
      <table>
        <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Details</th></tr></thead>
        <tbody>
          {packets.slice(0, 40).map(packet => (
            <tr key={packet.id}>
              <td>{new Date(packet.timestamp).toLocaleTimeString()}</td>
              <td>{packet.src_ip}</td>
              <td>{packet.dst_ip}{packet.dst_port ? `:${packet.dst_port}` : ''}</td>
              <td>{packet.protocol}</td>
              <td>{packet.dns_query || packet.tls_sni || packet.tcp_flags || packet.arp_op || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

function Metric({ label, value, tone }) {
  return <article className={`metric ${tone || ''}`}><span>{label}</span><strong>{value}</strong></article>;
}

function Panel({ title, children }) {
  return <section className="panel"><h2>{title}</h2>{children}</section>;
}

createRoot(document.getElementById('root')).render(<App />);
