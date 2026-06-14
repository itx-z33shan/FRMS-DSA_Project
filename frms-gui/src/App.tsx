import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Trash2, 
  Play, 
  Plus, 
  RefreshCw, 
  Search, 
  Database, 
  Network, 
  AlertTriangle,
  PlayCircle,
  Clock,
  Flame,
  ArrowRightLeft,
  X
} from 'lucide-react';
import { Firewall, Packet, Rule, LogEntry, MAX_PACKETS, MAX_RULES, HASH_TABLE_SIZE } from './utils/structures';

export default function App() {
  // Firewall State
  const [fw] = useState(() => new Firewall());
  
  // React mirror states to trigger re-renders
  const [packets, setPackets] = useState<Packet[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [bstIPs, setBstIPs] = useState<string[]>([]);
  const [heapRules, setHeapRules] = useState<Rule[]>([]);
  const [hashBuckets, setHashBuckets] = useState<{ index: number; chain: Rule[] }[]>([]);
  const [stats, setStats] = useState({ total: 0, blocked: 0, allowed: 0 });
  const [activeTab, setActiveTab] = useState<'queue' | 'hash' | 'heap' | 'bst' | 'logs'>('queue');

  // Interactive step feedback
  const [stepResult, setStepResult] = useState<{
    packet: Packet;
    action: "ALLOWED" | "BLOCKED";
    ruleID: string;
    priority: number;
    checkStep: string;
  } | null>(null);

  // Form states
  const [newRule, setNewRule] = useState({
    ruleID: 'R' + String(Math.floor(Math.random() * 900) + 100),
    targetIP: '192.168.1.100',
    action: 'BLOCK' as 'BLOCK' | 'ALLOW',
    priority: 5,
    protocol: 'TCP'
  });

  const [newPacket, setNewPacket] = useState({
    sourceIP: '192.168.1.10',
    destIP: '10.0.0.99',
    port: 80,
    protocol: 'TCP',
    size: 256
  });

  const [searchIP, setSearchIP] = useState('');
  const [searchResults, setSearchResults] = useState<LogEntry[]>([]);
  const [hasSearched, setHasSearched] = useState(false);

  // Sync state helper
  const syncState = () => {
    setPackets(fw.packetQueue.getElements());
    setLogs(fw.logManager.getLogs());
    setBstIPs(fw.ipTree.getSortedBlockedIPs());
    setHeapRules(fw.ruleHeap.getRawArray());
    setHashBuckets(fw.ruleTable.getBuckets());
    setStats({
      total: fw.totalProcessed,
      blocked: fw.logManager.getBlockedCount(),
      allowed: fw.logManager.getAllowedCount()
    });
    // Rules list from heap to see all rules loaded
    setRules(fw.ruleHeap.getRawArray());
  };

  // On mount
  useEffect(() => {
    // Load defaults on start
    fw.loadDefaults();
    syncState();
  }, []);

  // Handlers
  const handleLoadDefaults = () => {
    // Clear and reload
    fw.packetQueue = new (fw.packetQueue as any).constructor();
    fw.ruleTable = new (fw.ruleTable as any).constructor();
    fw.ruleHeap = new (fw.ruleHeap as any).constructor();
    fw.ipTree = new (fw.ipTree as any).constructor();
    fw.logManager = new (fw.logManager as any).constructor();
    fw.totalProcessed = 0;
    
    fw.loadDefaults();
    setStepResult(null);
    setSearchResults([]);
    setHasSearched(false);
    syncState();
  };

  const handleStepProcess = () => {
    if (fw.packetQueue.empty()) {
      alert("No packets in the queue! Add a packet manually or reload defaults.");
      return;
    }
    const result = fw.processNext();
    if (result) {
      setStepResult({
        packet: result.packet,
        action: result.decision.action,
        ruleID: result.decision.ruleID,
        priority: result.decision.priority,
        checkStep: result.decision.checkStep
      });
      syncState();
    }
  };

  const handleProcessAll = () => {
    if (fw.packetQueue.empty()) {
      alert("No packets in the queue! Add a packet manually or reload defaults.");
      return;
    }
    let processedCount = 0;
    while (!fw.packetQueue.empty()) {
      fw.processNext();
      processedCount++;
    }
    setStepResult(null);
    syncState();
    alert(`Successfully processed all ${processedCount} packets.`);
  };

  const handleReset = () => {
    // Re-instantiate everything empty
    fw.packetQueue = new (fw.packetQueue as any).constructor();
    fw.ruleTable = new (fw.ruleTable as any).constructor();
    fw.ruleHeap = new (fw.ruleHeap as any).constructor();
    fw.ipTree = new (fw.ipTree as any).constructor();
    fw.logManager = new (fw.logManager as any).constructor();
    fw.totalProcessed = 0;
    setStepResult(null);
    setSearchResults([]);
    setHasSearched(false);
    syncState();
  };

  const handleAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.targetIP.trim()) {
      alert("IP Address is required.");
      return;
    }
    const rule = new Rule(
      newRule.ruleID,
      newRule.targetIP.trim(),
      newRule.action,
      Number(newRule.priority),
      newRule.protocol
    );
    fw.addRule(rule);
    syncState();
    // regenerate rule id
    setNewRule(prev => ({
      ...prev,
      ruleID: 'R' + String(Math.floor(Math.random() * 900) + 100)
    }));
  };

  const handleAddPacket = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPacket.sourceIP.trim() || !newPacket.destIP.trim()) {
      alert("Source and Destination IPs are required.");
      return;
    }
    const p = new Packet(
      newPacket.sourceIP.trim(),
      newPacket.destIP.trim(),
      Number(newPacket.port),
      newPacket.protocol,
      Number(newPacket.size)
    );
    const success = fw.packetQueue.push(p);
    if (success) {
      syncState();
    } else {
      alert("Packet Queue is full!");
    }
  };

  const handleRemoveRule = (ip: string) => {
    const success = fw.removeRule(ip);
    if (success) {
      syncState();
    } else {
      alert("No rule found for this IP.");
    }
  };

  const handleSearchLogs = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchIP.trim()) {
      setSearchResults([]);
      setHasSearched(false);
      return;
    }
    // Perform binary search on logs
    const results = fw.logManager.binarySearchByIP(searchIP.trim());
    setSearchResults(results);
    setHasSearched(true);
  };

  const handleSortLogs = (type: 'time' | 'severity') => {
    if (type === 'time') {
      fw.logManager.sortByTimestamp();
    } else {
      fw.logManager.sortBySeverity();
    }
    syncState();
  };

  // BST Tree Visualization layout
  const renderBSTNode = (node: any, x: number, y: number, dx: number): React.ReactNode[] => {
    if (!node) return [];
    const elements: React.ReactNode[] = [];
    
    if (node.left) {
      elements.push(
        <line 
          key={`line-l-${node.ip}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke="#1e2d54" strokeWidth="2"
        />
      );
      elements.push(...renderBSTNode(node.left, x - dx, y + 50, dx * 0.5));
    }
    if (node.right) {
      elements.push(
        <line 
          key={`line-r-${node.ip}`}
          x1={x} y1={y} x2={x + dx} y2={y + 50} 
          stroke="#1e2d54" strokeWidth="2"
        />
      );
      elements.push(...renderBSTNode(node.right, x + dx, y + 50, dx * 0.5));
    }
    
    elements.push(
      <g key={`node-${node.ip}`} className="group cursor-pointer">
        <circle 
          cx={x} cy={y} r="16" 
          fill="#11192e" stroke="#06b6d4" strokeWidth="2" 
          className="transition-all duration-300 hover:fill-cyber-cardLight hover:stroke-cyber-emerald"
        />
        <text 
          x={x} y={y + 4} 
          textAnchor="middle" fill="#e2e8f0" fontSize="8" fontWeight="bold"
          className="pointer-events-none"
        >
          {node.ip.split('.').slice(-2).join('.')}
        </text>
        <title>{`Blocked IP: ${node.ip}`}</title>
      </g>
    );
    
    return elements;
  };

  // Max-Heap Binary Tree Layout
  const renderHeapNode = (idx: number, x: number, y: number, dx: number): React.ReactNode[] => {
    if (idx >= heapRules.length) return [];
    const elements: React.ReactNode[] = [];
    const leftIdx = 2 * idx + 1;
    const rightIdx = 2 * idx + 2;
    const rule = heapRules[idx];
    
    if (leftIdx < heapRules.length) {
      elements.push(
        <line 
          key={`h-line-l-${idx}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke="#1e2d54" strokeWidth="2"
        />
      );
      elements.push(...renderHeapNode(leftIdx, x - dx, y + 50, dx * 0.5));
    }
    
    if (rightIdx < heapRules.length) {
      elements.push(
        <line 
          key={`h-line-r-${idx}`}
          x1={x} y1={y} x2={x + dx} y2={y + 50} 
          stroke="#1e2d54" strokeWidth="2"
        />
      );
      elements.push(...renderHeapNode(rightIdx, x + dx, y + 50, dx * 0.5));
    }
    
    elements.push(
      <g key={`h-node-${idx}`} className="group cursor-pointer">
        <circle 
          cx={x} cy={y} r="17" 
          fill="#11192e" 
          stroke={rule.action === "BLOCK" ? "#f43f5e" : "#10b981"} 
          strokeWidth="2" 
          className="transition-all duration-300 hover:fill-cyber-cardLight"
        />
        <text 
          x={x} y={y + 1} 
          textAnchor="middle" fill="#e2e8f0" fontSize="8" fontWeight="bold"
          className="pointer-events-none"
        >
          {rule.ruleID}
        </text>
        <text 
          x={x} y={y + 9} 
          textAnchor="middle" fill="#94a3b8" fontSize="6.5"
          className="pointer-events-none"
        >
          P:{rule.priority}
        </text>
        <title>{`${rule.ruleID} | IP: ${rule.targetIP} | Action: ${rule.action} | Priority: ${rule.priority}`}</title>
      </g>
    );
    
    return elements;
  };

  const blockRate = stats.total > 0 ? Math.round((stats.blocked / stats.total) * 100) : 0;

  return (
    <div className="min-h-screen bg-cyber-darker text-cyber-text grid-bg relative overflow-x-hidden scanline">
      
      {/* GLOW DECORATIONS */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-cyan/5 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-cyber-emerald/5 rounded-full blur-[120px] pointer-events-none"></div>

      {/* HEADER */}
      <header className="border-b border-cyber-border bg-cyber-dark/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-cyan/10 rounded-lg border border-cyber-cyan/30 glow-pulse-cyan">
              <Shield className="w-8 h-8 text-cyber-cyan" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-cyber-emerald">
                FIREWALL RULE MANAGEMENT SYSTEM
              </h1>
              <p className="text-xs text-cyber-textMuted font-mono">
                A Cybersecurity Simulation Using Custom Data Structures
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4 font-mono text-xs text-cyber-textMuted bg-cyber-card/60 p-2 rounded-lg border border-cyber-border">
            <span>Course: CSC211</span>
            <span className="text-cyber-border">|</span>
            <span>Team: Attaullah, Monis, Zeeshan</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        
        {/* STATS MATRIX */}
        <section className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border shadow-glow shadow-cyan-950/20 flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase">Processed</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-cyan">{stats.total}</span>
              <span className="text-xs text-cyber-textMuted">packets</span>
            </div>
          </div>
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border shadow-glow shadow-rose-950/20 flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-cyber-rose" /> Blocked
            </span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-rose">{stats.blocked}</span>
            </div>
          </div>
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border shadow-glow shadow-emerald-950/20 flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-cyber-emerald" /> Allowed
            </span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-emerald">{stats.allowed}</span>
            </div>
          </div>
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase">Block Rate</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-amber">{blockRate}%</span>
            </div>
          </div>
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase">Queue size</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-text">{packets.length}</span>
              <span className="text-xs text-cyber-textMuted">/ {MAX_PACKETS}</span>
            </div>
          </div>
          <div className="bg-cyber-card p-4 rounded-xl border border-cyber-border flex flex-col justify-between">
            <span className="text-xs font-mono text-cyber-textMuted uppercase">Rules</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-bold font-mono text-cyber-text">{rules.length}</span>
              <span className="text-xs text-cyber-textMuted">/ {MAX_RULES}</span>
            </div>
          </div>
        </section>

        {/* BATCH ACTION CONTROLLER */}
        <section className="bg-cyber-card border border-cyber-border p-4 rounded-xl flex flex-wrap justify-between items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-cyber-cyan uppercase tracking-wider">Firewall Core:</span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald font-bold uppercase tracking-wider">Active simulation</span>
          </div>
          <div className="flex flex-wrap gap-2.5">
            <button 
              onClick={handleLoadDefaults}
              className="px-3 py-1.5 rounded-lg bg-cyber-border border border-cyber-border text-xs font-mono font-bold hover:bg-cyber-cardLight transition flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Load Defaults
            </button>
            <button 
              onClick={handleStepProcess}
              className="px-3 py-1.5 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono font-bold hover:bg-cyber-cyan/20 transition flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-cyber-cyan" /> Step Packet
            </button>
            <button 
              onClick={handleProcessAll}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyber-cyan text-white text-xs font-mono font-bold hover:brightness-110 transition flex items-center gap-1.5"
            >
              <PlayCircle className="w-3.5 h-3.5" /> Process Queue
            </button>
            <button 
              onClick={handleReset}
              className="px-3 py-1.5 rounded-lg bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose text-xs font-mono font-bold hover:bg-cyber-rose/20 transition flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" /> Reset Firewall
            </button>
          </div>
        </section>

        {/* TWO COLUMN GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* LEFT COLUMN: CONTROL & OPERATIONS PANEL */}
          <div className="lg:col-span-4 space-y-6">
            
            {/* STEP DECISION MODAL/ALERT */}
            {stepResult && (
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 shadow-lg animate-fade-in relative overflow-hidden">
                <div className={`absolute top-0 left-0 w-1.5 h-full ${stepResult.action === "BLOCKED" ? "bg-cyber-rose" : "bg-cyber-emerald"}`}></div>
                <div className="flex justify-between items-start mb-2">
                  <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${stepResult.action === "BLOCKED" ? "bg-cyber-rose/10 text-cyber-rose" : "bg-cyber-emerald/10 text-cyber-emerald"}`}>
                    {stepResult.action}
                  </span>
                  <button onClick={() => setStepResult(null)} className="text-cyber-textMuted hover:text-cyber-text">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-2">STEP PROCESSING FEEDBACK</h4>
                <div className="bg-cyber-darker p-2.5 rounded border border-cyber-border font-mono text-xs space-y-1.5">
                  <div className="flex justify-between"><span className="text-cyber-textMuted">Src IP:</span><span>{stepResult.packet.sourceIP}</span></div>
                  <div className="flex justify-between"><span className="text-cyber-textMuted">Dest IP:</span><span>{stepResult.packet.destIP}</span></div>
                  <div className="flex justify-between"><span className="text-cyber-textMuted">Port:</span><span>{stepResult.packet.port} ({stepResult.packet.protocol})</span></div>
                  <div className="flex justify-between"><span className="text-cyber-textMuted">Rule Match:</span><span className="text-cyber-cyan">{stepResult.ruleID}</span></div>
                  <div className="flex justify-between"><span className="text-cyber-textMuted">Priority:</span><span>{stepResult.priority}</span></div>
                  <div className="text-[10px] text-cyber-textMuted border-t border-cyber-border/40 pt-1 mt-1 text-center font-sans italic">
                    Decision Source: {stepResult.checkStep}
                  </div>
                </div>
              </div>
            )}

            {/* RULE FORM */}
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
              <h2 className="text-sm font-bold font-mono tracking-wider text-cyber-cyan flex items-center gap-2 mb-4 uppercase">
                <Plus className="w-4 h-4" /> Add Firewall Rule
              </h2>
              <form onSubmit={handleAddRule} className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Rule ID</label>
                    <input 
                      type="text" 
                      value={newRule.ruleID}
                      onChange={e => setNewRule(prev => ({ ...prev, ruleID: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan"
                    />
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Target IP</label>
                    <input 
                      type="text" 
                      value={newRule.targetIP}
                      onChange={e => setNewRule(prev => ({ ...prev, targetIP: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan"
                      placeholder="192.168.1.100"
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Action</label>
                    <select 
                      value={newRule.action} 
                      onChange={e => setNewRule(prev => ({ ...prev, action: e.target.value as any }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan"
                    >
                      <option value="BLOCK">BLOCK</option>
                      <option value="ALLOW">ALLOW</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Priority (1-10)</label>
                    <input 
                      type="number" 
                      min="1" 
                      max="10" 
                      value={newRule.priority}
                      onChange={e => setNewRule(prev => ({ ...prev, priority: Number(e.target.value) }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan"
                    />
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Protocol</label>
                    <select 
                      value={newRule.protocol} 
                      onChange={e => setNewRule(prev => ({ ...prev, protocol: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan"
                    >
                      <option value="ANY">ANY</option>
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="HTTP">HTTP</option>
                    </select>
                  </div>
                </div>

                <button 
                  type="submit" 
                  className="w-full mt-2 py-2 rounded bg-cyber-cyan/15 hover:bg-cyber-cyan/35 border border-cyber-cyan/40 text-cyber-cyan font-bold transition flex items-center justify-center gap-1.5"
                >
                  <Plus className="w-4 h-4" /> Insert to HashTable & Heap
                </button>
              </form>
            </div>

            {/* PACKET FORM */}
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
              <h2 className="text-sm font-bold font-mono tracking-wider text-cyber-emerald flex items-center gap-2 mb-4 uppercase">
                <Plus className="w-4 h-4" /> Queue Packet Manually
              </h2>
              <form onSubmit={handleAddPacket} className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Source IP</label>
                    <input 
                      type="text" 
                      value={newPacket.sourceIP}
                      onChange={e => setNewPacket(prev => ({ ...prev, sourceIP: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald"
                    />
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Dest IP</label>
                    <input 
                      type="text" 
                      value={newPacket.destIP}
                      onChange={e => setNewPacket(prev => ({ ...prev, destIP: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Port</label>
                    <input 
                      type="number" 
                      value={newPacket.port}
                      onChange={e => setNewPacket(prev => ({ ...prev, port: Number(e.target.value) }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald"
                    />
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Protocol</label>
                    <select 
                      value={newPacket.protocol} 
                      onChange={e => setNewPacket(prev => ({ ...prev, protocol: e.target.value }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald"
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="HTTP">HTTP</option>
                      <option value="ANY">ANY</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-cyber-textMuted mb-1">Size (B)</label>
                    <input 
                      type="number" 
                      value={newPacket.size}
                      onChange={e => setNewPacket(prev => ({ ...prev, size: Number(e.target.value) }))}
                      className="w-full bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald"
                    />
                  </div>
                </div>

                <button 
                  type="submit" 
                  className="w-full mt-2 py-2 rounded bg-cyber-emerald/15 hover:bg-cyber-emerald/35 border border-cyber-emerald/40 text-cyber-emerald font-bold transition flex items-center justify-center gap-1.5"
                >
                  <Plus className="w-4 h-4" /> Push to Circular Queue
                </button>
              </form>
            </div>

            {/* LOG SEARCH BINARY SEARCH */}
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
              <h2 className="text-sm font-bold font-mono tracking-wider text-cyber-amber flex items-center gap-2 mb-4 uppercase">
                <Search className="w-4 h-4" /> Binary Search Logs
              </h2>
              <form onSubmit={handleSearchLogs} className="space-y-3 font-mono text-xs">
                <div>
                  <label className="block text-cyber-textMuted mb-1">Search Source IP (Exact)</label>
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      value={searchIP}
                      onChange={e => setSearchIP(e.target.value)}
                      placeholder="e.g. 192.168.1.10"
                      className="flex-1 bg-cyber-darker border border-cyber-border p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-amber"
                    />
                    <button 
                      type="submit" 
                      className="px-4 py-2 bg-cyber-amber/15 border border-cyber-amber/40 hover:bg-cyber-amber/30 text-cyber-amber font-bold rounded transition flex items-center gap-1"
                    >
                      <Search className="w-3.5 h-3.5" /> Run
                    </button>
                  </div>
                </div>
              </form>

              {/* SEARCH RESULTS DISPLAY */}
              {hasSearched && (
                <div className="mt-4 border-t border-cyber-border/60 pt-3 space-y-2 max-h-[200px] overflow-y-auto">
                  <h4 className="text-[10px] font-bold font-mono text-cyber-textMuted uppercase flex justify-between">
                    <span>Search Results ({searchResults.length}):</span>
                    <button onClick={() => { setHasSearched(false); setSearchIP(''); }} className="text-cyber-rose">Clear</button>
                  </h4>
                  {searchResults.length === 0 ? (
                    <p className="text-xs text-cyber-textMuted font-mono italic">No logs found for this IP.</p>
                  ) : (
                    searchResults.map((log, idx) => (
                      <div key={`search-${idx}`} className="bg-cyber-darker p-2 rounded border border-cyber-border font-mono text-[11px] flex justify-between items-center">
                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className={log.action === "BLOCKED" ? "text-cyber-rose" : "text-cyber-emerald"}>●</span>
                            <span>{log.sourceIP}</span>
                            <span className="text-cyber-textMuted">→</span>
                            <span className="text-cyber-cyan">Port {log.port}</span>
                          </div>
                          <div className="text-[9px] text-cyber-textMuted mt-0.5">{log.timestamp}</div>
                        </div>
                        <span className="text-cyber-textMuted font-bold">{log.ruleID}</span>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

          </div>

          {/* RIGHT COLUMN: TABBED VISUALIZATIONS */}
          <div className="lg:col-span-8 flex flex-col bg-cyber-card border border-cyber-border rounded-xl shadow-lg overflow-hidden min-h-[600px]">
            
            {/* TABS SELECTOR */}
            <div className="flex flex-wrap border-b border-cyber-border bg-cyber-dark/40 font-mono text-xs">
              <button 
                onClick={() => setActiveTab('queue')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border font-bold transition ${activeTab === 'queue' ? 'bg-cyber-card text-cyber-emerald border-t-2 border-t-cyber-emerald' : 'text-cyber-textMuted hover:bg-cyber-cardLight hover:text-cyber-text'}`}
              >
                <Activity className="w-4 h-4" /> Queue Buffer
              </button>
              <button 
                onClick={() => setActiveTab('hash')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border font-bold transition ${activeTab === 'hash' ? 'bg-cyber-card text-cyber-cyan border-t-2 border-t-cyber-cyan' : 'text-cyber-textMuted hover:bg-cyber-cardLight hover:text-cyber-text'}`}
              >
                <Database className="w-4 h-4" /> Hash Table (Rules)
              </button>
              <button 
                onClick={() => setActiveTab('heap')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border font-bold transition ${activeTab === 'heap' ? 'bg-cyber-card text-cyber-rose border-t-2 border-t-cyber-rose' : 'text-cyber-textMuted hover:bg-cyber-cardLight hover:text-cyber-text'}`}
              >
                <Flame className="w-4 h-4" /> Max-Heap (Priorities)
              </button>
              <button 
                onClick={() => setActiveTab('bst')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border font-bold transition ${activeTab === 'bst' ? 'bg-cyber-card text-cyber-cyan border-t-2 border-t-cyber-cyan' : 'text-cyber-textMuted hover:bg-cyber-cardLight hover:text-cyber-text'}`}
              >
                <Network className="w-4 h-4" /> BST (Blocked IPs)
              </button>
              <button 
                onClick={() => setActiveTab('logs')}
                className={`flex items-center gap-1.5 px-4 py-3 font-bold transition ${activeTab === 'logs' ? 'bg-cyber-card text-cyber-amber border-t-2 border-t-cyber-amber' : 'text-cyber-textMuted hover:bg-cyber-cardLight hover:text-cyber-text'}`}
              >
                <Clock className="w-4 h-4" /> Sorting & Logs
              </button>
            </div>

            {/* TAB CONTENTS */}
            <div className="p-6 flex-1 flex flex-col">
              
              {/* TAB 1: PACKET QUEUE */}
              {activeTab === 'queue' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div>
                    <h3 className="text-sm font-bold font-mono text-cyber-emerald uppercase tracking-wider mb-1">Packet Processing Queue (FIFO circular array)</h3>
                    <p className="text-xs text-cyber-textMuted font-mono">
                      Packets arrive in circular buffer. First in, first out. Drag/slide to view indices. Next item to process is shown at index <span className="text-cyber-emerald font-bold">{fw.packetQueue.getFrontIdx()}</span>.
                    </p>
                  </div>
                  
                  {packets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      <AlertTriangle className="w-8 h-8 text-cyber-amber mb-2" />
                      Queue is currently empty! Add packets or load defaults above.
                    </div>
                  ) : (
                    <div className="space-y-6 flex-1 flex flex-col justify-center">
                      
                      {/* FIFO CONVEYOR VIEW */}
                      <div className="flex items-center justify-center p-4 bg-cyber-darker border border-cyber-border rounded-xl gap-2 overflow-x-auto select-none py-8">
                        {packets.map((pkt, idx) => (
                          <React.Fragment key={`conveyor-${idx}`}>
                            {idx > 0 && <span className="text-cyber-border font-bold">➔</span>}
                            <div className={`flex-shrink-0 w-[140px] bg-cyber-card border p-3 rounded-lg font-mono text-[10px] space-y-1 relative transition-all duration-300 shadow ${idx === 0 ? 'border-cyber-emerald bg-cyber-cyan/5 filter drop-shadow-[0_0_4px_rgba(16,185,129,0.25)]' : 'border-cyber-border'}`}>
                              {idx === 0 && (
                                <span className="absolute top-[-8px] right-2 px-1 rounded text-[7px] bg-cyber-emerald text-cyber-darker font-bold uppercase tracking-wider">NEXT</span>
                              )}
                              <div className="font-bold text-cyber-text truncate">{pkt.sourceIP}</div>
                              <div className="text-cyber-textMuted truncate">→ {pkt.destIP}</div>
                              <div className="text-cyber-cyan">Port: {pkt.port}</div>
                              <div className="text-cyber-textMuted">Proto: {pkt.protocol}</div>
                              <div className="text-cyber-textMuted">Size: {pkt.size}B</div>
                            </div>
                          </React.Fragment>
                        ))}
                      </div>

                      {/* RAW CIRCULAR ARRAY VIEW */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-xs font-bold font-mono text-cyber-textMuted">Circular Array Buffer Index Diagram (Cap: {MAX_PACKETS})</span>
                          <div className="flex gap-4 font-mono text-[10px]">
                            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-cyber-emerald rounded"></span> Front ({fw.packetQueue.getFrontIdx()})</span>
                            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-blue-500 rounded"></span> Rear ({fw.packetQueue.getRearIdx()})</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-8 sm:grid-cols-12 gap-1.5 font-mono text-center">
                          {Array.from({ length: 24 }).map((_, idx) => {
                            // Show first 24 slots representing circular behavior
                            const rawArray = fw.packetQueue.getRawArray();
                            const hasP = rawArray[idx] !== null;
                            const isFront = idx === fw.packetQueue.getFrontIdx();
                            const isRear = idx === fw.packetQueue.getRearIdx();
                            
                            let bgClass = "bg-cyber-card/40 border-cyber-border/40 text-cyber-textMuted";
                            if (hasP) bgClass = "bg-cyber-card border-cyber-border text-cyber-text";
                            if (isFront) bgClass = "bg-cyber-emerald/10 border-cyber-emerald text-cyber-emerald font-bold";
                            if (isRear) bgClass = "bg-blue-950/20 border-blue-500 text-blue-400 font-bold";

                            return (
                              <div 
                                key={`circular-${idx}`}
                                className={`border rounded p-1 text-[9px] relative flex flex-col justify-between h-12 transition-all ${bgClass}`}
                              >
                                <span className="text-[7px] text-cyber-textMuted">#{idx}</span>
                                <span className="font-bold truncate">{hasP ? 'PKT' : 'ø'}</span>
                                <div className="absolute bottom-[-5px] left-1/2 transform -translate-x-1/2 flex gap-0.5">
                                  {isFront && <span className="w-1.5 h-1.5 bg-cyber-emerald rounded-full"></span>}
                                  {isRear && <span className="w-1.5 h-1.5 bg-blue-500 rounded-full"></span>}
                                </div>
                              </div>
                            );
                          })}
                          <div className="col-span-full text-[9px] text-cyber-textMuted text-right font-sans italic pt-1">
                            *Displaying first 24 slots of {MAX_PACKETS} capacity circular slots.
                          </div>
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: HASH TABLE */}
              {activeTab === 'hash' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div>
                    <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-1">Rule Lookup Hash Table (Polynomial Chaining)</h3>
                    <p className="text-xs text-cyber-textMuted font-mono">
                      Rules are inserted using polynomial rolling hash `H(IP) = Σ (c_i * 31^i) % 101`. Collisions prepended to linked chains.
                    </p>
                  </div>
                  
                  {hashBuckets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No rules loaded! Load default configurations.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* BUCKET SCROLL GRID */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col max-h-[400px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan mb-3">Active Hash Buckets (Size: {HASH_TABLE_SIZE})</h4>
                        <div className="flex-1 overflow-y-auto space-y-2.5 pr-2">
                          {hashBuckets.map((bucket) => (
                            <div key={`bucket-${bucket.index}`} className="bg-cyber-card border border-cyber-border rounded p-2.5 font-mono text-xs flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <span className="px-2 py-0.5 bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-[10px] rounded font-bold">
                                  Bucket {bucket.index}
                                </span>
                                <span className="text-cyber-textMuted text-[10px]">
                                  Chain length: {bucket.chain.length}
                                </span>
                              </div>
                              <div className="flex items-center gap-1 overflow-x-auto max-w-[200px]">
                                {bucket.chain.map((rule, idx) => (
                                  <span 
                                    key={`chain-${bucket.index}-${idx}`}
                                    className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${rule.action === "BLOCK" ? "bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/20" : "bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/20"}`}
                                    title={`Rule: ${rule.ruleID}\nIP: ${rule.targetIP}\nPriority: ${rule.priority}`}
                                  >
                                    {rule.ruleID}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* DETAILED ACTIVE RULES LIST */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col max-h-[400px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-3">All Active Rules ({rules.length})</h4>
                        <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                          {rules.map((rule) => (
                            <div key={`rule-list-${rule.ruleID}`} className="bg-cyber-card border border-cyber-border rounded p-2.5 font-mono text-xs flex justify-between items-center transition-all hover:bg-cyber-cardLight">
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-bold">{rule.ruleID}</span>
                                  <span className={`px-1 text-[8px] font-bold rounded ${rule.action === "BLOCK" ? "bg-cyber-rose/10 text-cyber-rose" : "bg-cyber-emerald/10 text-cyber-emerald"}`}>
                                    {rule.action}
                                  </span>
                                </div>
                                <div className="text-[10px] text-cyber-textMuted mt-1">IP: {rule.targetIP}</div>
                                <div className="text-[9px] text-cyber-cyan mt-0.5">Hits: {rule.hitCount} | Proto: {rule.protocol} | Priority: {rule.priority}</div>
                              </div>
                              <button 
                                onClick={() => handleRemoveRule(rule.targetIP)}
                                className="p-1 hover:text-cyber-rose text-cyber-textMuted transition"
                                title="Remove Rule"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: MAX-HEAP */}
              {activeTab === 'heap' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div>
                    <h3 className="text-sm font-bold font-mono text-cyber-rose uppercase tracking-wider mb-1">Priority Rule Max-Heap (Array Index Hierarchy)</h3>
                    <p className="text-xs text-cyber-textMuted font-mono">
                      Rules organized by priority. Highest priority rule is always at root (index 0). Children indices calculated as `left = 2*i + 1`, `right = 2*i + 2`.
                    </p>
                  </div>
                  
                  {heapRules.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No rules loaded! Load defaults above.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE RENDER CONTAINER */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col items-center justify-center min-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-rose self-start mb-4">Max-Heap Binary Tree Layout</h4>
                        <div className="w-full flex justify-center overflow-x-auto overflow-y-hidden">
                          <svg width="400" height="200" className="flex-shrink-0">
                            {renderHeapNode(0, 200, 25, 90)}
                          </svg>
                        </div>
                      </div>

                      {/* HEAP ARRAY FLAT VIEW */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col">
                        <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-3">Flat Max-Heap Array Memory Representation</h4>
                        <div className="grid grid-cols-5 gap-2 font-mono text-center overflow-y-auto max-h-[300px] pr-1">
                          {heapRules.map((rule, idx) => (
                            <div 
                              key={`flat-heap-${idx}`} 
                              className={`border rounded p-1.5 text-[10px] space-y-1 relative flex flex-col justify-between ${idx === 0 ? 'bg-cyber-rose/10 border-cyber-rose text-cyber-rose' : 'bg-cyber-card border-cyber-border'}`}
                            >
                              <span className="text-[7.5px] text-cyber-textMuted absolute top-0.5 left-1">#{idx}</span>
                              <div className="font-bold pt-2">{rule.ruleID}</div>
                              <div className="text-[8.5px] font-bold">Pri: {rule.priority}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: BST */}
              {activeTab === 'bst' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div>
                    <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-1">Blocked IPs Range BST (Binary Search Tree)</h3>
                    <p className="text-xs text-cyber-textMuted font-mono">
                      Stores blocked rule IP addresses in sorted order. Fast `O(log n)` check if an arriving packet IP is blacklisted.
                    </p>
                  </div>
                  
                  {bstIPs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No blocked rules are active! Inser a BLOCK rule.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE SVG DIAGRAM */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col items-center justify-center min-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan self-start mb-4">BST Block Index Visualizer</h4>
                        <div className="w-full flex justify-center overflow-x-auto overflow-y-hidden">
                          <svg width="400" height="200" className="flex-shrink-0">
                            {renderBSTNode(fw.ipTree.getRoot(), 200, 25, 90)}
                          </svg>
                        </div>
                      </div>

                      {/* IN-ORDER SORTED LIST */}
                      <div className="bg-cyber-darker border border-cyber-border rounded-xl p-4 flex flex-col max-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan mb-3">Sorted IP Blocking Index (BST In-Order)</h4>
                        <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                          {bstIPs.map((ip, idx) => (
                            <div key={`bst-ip-${idx}`} className="bg-cyber-card border border-cyber-border rounded p-2 font-mono text-xs flex justify-between items-center transition-all hover:bg-cyber-cardLight">
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] text-cyber-textMuted">#{idx + 1}</span>
                                <span className="font-bold text-cyber-rose">{ip}</span>
                              </div>
                              <span className="text-[10px] text-cyber-textMuted">Lexicographical sort</span>
                            </div>
                          ))}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: LOGS & SORTING */}
              {activeTab === 'logs' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div>
                    <h3 className="text-sm font-bold font-mono text-cyber-amber uppercase tracking-wider mb-1">Logs Manager & Sorting Visualizer</h3>
                    <p className="text-xs text-cyber-textMuted font-mono">
                      Compare Quick Sort (O(n log n) by timestamp) and Merge Sort (O(n log n) by severity priority).
                    </p>
                  </div>

                  {/* SORT CONTROLS & METRICS */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-cyber-darker border border-cyber-border p-4 rounded-xl">
                    <div>
                      <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-3">Sort Storage Array</h4>
                      <div className="flex gap-2.5">
                        <button 
                          onClick={() => handleSortLogs('time')}
                          className="px-3.5 py-2 rounded bg-cyber-cyan/15 hover:bg-cyber-cyan/30 border border-cyber-cyan/40 text-cyber-cyan font-bold font-mono text-xs transition flex items-center gap-1.5"
                        >
                          <Clock className="w-4 h-4" /> Quick Sort (Timestamp)
                        </button>
                        <button 
                          onClick={() => handleSortLogs('severity')}
                          className="px-3.5 py-2 rounded bg-cyber-amber/15 hover:bg-cyber-amber/30 border border-cyber-amber/40 text-cyber-amber font-bold font-mono text-xs transition flex items-center gap-1.5"
                        >
                          <ArrowRightLeft className="w-4 h-4" /> Merge Sort (Severity)
                        </button>
                      </div>
                    </div>

                    <div className="bg-cyber-card/60 border border-cyber-border rounded p-3 font-mono text-[11px] space-y-1">
                      <div className="text-cyber-textMuted font-bold border-b border-cyber-border/40 pb-1 mb-1.5 uppercase">Algorithm Benchmark Statistics</div>
                      <div className="flex justify-between"><span>Comparisons:</span><span className="text-cyber-cyan font-bold">{fw.logManager.sortMetrics.comparisons}</span></div>
                      <div className="flex justify-between"><span>Array Writes/Swaps:</span><span className="text-cyber-cyan font-bold">{fw.logManager.sortMetrics.swaps}</span></div>
                      <div className="flex justify-between"><span>Time Taken:</span><span className="text-cyber-emerald font-bold">{fw.logManager.sortMetrics.timeTakenMs} ms</span></div>
                    </div>
                  </div>

                  {/* LOGS TABLE */}
                  {logs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No logs recorded yet. Start processing packets!
                    </div>
                  ) : (
                    <div className="border border-cyber-border rounded-xl overflow-hidden flex-1 max-h-[350px] overflow-y-auto">
                      <table className="w-full text-left font-mono text-xs border-collapse">
                        <thead className="bg-cyber-darker text-cyber-textMuted border-b border-cyber-border sticky top-0">
                          <tr>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3">Action</th>
                            <th className="p-3">Source IP</th>
                            <th className="p-3">Port</th>
                            <th className="p-3">Matched Rule</th>
                            <th className="p-3 text-right">Pri</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-cyber-border/40">
                          {logs.map((log, idx) => (
                            <tr key={`log-${idx}`} className="hover:bg-cyber-cardLight/50 transition">
                              <td className="p-3 text-cyber-textMuted whitespace-nowrap">{log.timestamp}</td>
                              <td className="p-3 font-bold">
                                <span className={log.action === "BLOCKED" ? "text-cyber-rose" : "text-cyber-emerald"}>
                                  {log.action}
                                </span>
                              </td>
                              <td className="p-3">{log.sourceIP}</td>
                              <td className="p-3 text-cyber-cyan">{log.port} <span className="text-[10px] text-cyber-textMuted">({log.protocol})</span></td>
                              <td className="p-3 text-cyber-textMuted">{log.ruleID}</td>
                              <td className="p-3 text-right font-bold">{log.priority}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

            </div>
          </div>

        </div>

      </main>

      <footer className="border-t border-cyber-border/80 bg-cyber-dark/80 backdrop-blur py-6 mt-12 text-center text-xs text-cyber-textMuted font-mono">
        <p>© 2026 FRMS (Firewall Rule Management System) Cybersecurity Simulation.</p>
        <p className="mt-1 text-[10px] text-cyber-border">Built with React + TailwindCSS + WASM-ready TS structures.</p>
      </footer>

    </div>
  );
}
