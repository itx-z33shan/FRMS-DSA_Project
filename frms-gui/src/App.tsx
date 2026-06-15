import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
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
import { MaxHeap, Firewall, Packet, Rule, LogEntry, MAX_PACKETS, MAX_RULES, HASH_TABLE_SIZE, BSTNode } from './utils/structures';
import type { HeapTraceStep, SortTraceStep } from './utils/structures';

interface StepperStep {
  message: string;
  simpleExplanation: string;
  tab: 'queue' | 'hash' | 'heap' | 'bst' | 'logs';
  highlights?: {
    queueFront?: boolean;
    queueRear?: boolean;
    activeQueueIdx?: number;
    hashBucketIdx?: number;
    hashChainKeys?: string[];
    hashActiveKey?: string;
    heapComparing?: [number, number];
    heapSwapping?: [number, number];
    bstPath?: string[];
    bstActiveNode?: string;
    sortComparing?: [number, number];
    sortSwapping?: [number, number];
  };
  stateSnapshot?: {
    packets?: Packet[];
    rules?: Rule[];
    logs?: LogEntry[];
    heapRules?: Rule[];
    hashBuckets?: { index: number; chain: Rule[] }[];
    bstIPs?: string[];
  };
}

const getHeapSimpleExplanation = (msg: string): string => {
  if (msg.includes("Comparing parent")) {
    return "⚖️ Priority Comparison: We are comparing this rule's priority with its parent rule to see if it should be higher up.";
  }
  if (msg.includes("Swapping index")) {
    return "🔄 Swapping Rules: This rule has a higher priority, so we swap it with its parent to move it up the priority tree.";
  }
  if (msg.includes("Heap property satisfied") || msg.includes("Heap property restored")) {
    return "✅ Priority Ladder Sorted: The heap rule property is satisfied. The highest priority rules are correctly positioned at the top.";
  }
  if (msg.includes("Inserted Rule")) {
    return "➕ Rule Placed: We inserted the new rule at the bottom index of our heap hierarchy. Now we will bubble it up to its correct priority place.";
  }
  if (msg.includes("Moved last rule")) {
    return "🔄 Re-arranging Heap: We moved the last rule to the root position. Now we will bubble it down to satisfy priority rules.";
  }
  if (msg.includes("Comparing left child") || msg.includes("Comparing right child")) {
    return "⚖️ Child Priority Check: We compare the parent rule's priority with its children to find the highest priority rule.";
  }
  if (msg.includes("Removed the only rule")) {
    return "🗑️ Removed Rule: The only rule in the heap was popped. The priority ladder is now empty.";
  }
  return msg;
};

const getSortSimpleExplanation = (msg: string): string => {
  if (msg.includes("Comparing index") && msg.includes("pivot")) {
    return "⚖️ Comparing to Pivot: We compare this log entry's date with our partition pivot point to see if it belongs before or after.";
  }
  if (msg.includes("<= pivot. Swapping")) {
    return "🔄 Swapping Entries: This log entry is older than or equal to our pivot, so we swap it into the older files section.";
  }
  if (msg.includes("Placing pivot")) {
    return "📍 Positioning Pivot: We place our partition pivot in its correct sorted position and swap elements.";
  }
  if (msg.includes("Comparing priority")) {
    return "⚖️ Comparing Severity: We compare the severity priority level of these two log entries to decide which is more urgent.";
  }
  if (msg.includes("Left index is higher") || msg.includes("Right index is higher")) {
    return "📋 Sorting Priority: We copy the higher severity log entry into our temporary sorted storage.";
  }
  if (msg.includes("Copying remaining")) {
    return "📋 Copying Remaining: We copy the remaining pre-sorted logs into our main array.";
  }
  if (msg.includes("completed")) {
    return "✅ Sorting Complete: All firewall logs have been successfully sorted in order!";
  }
  return msg;
};

const isValidIP = (ip: string): boolean => {
  const ipPattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (!ipPattern.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  return parts.every(part => part >= 0 && part <= 255);
};

interface NetworkParticle {
  id: number;
  startX: number;
  startY: number;
  endX: number;
  endY: number;
  x: number;
  y: number;
  progress: number;
  speed: number;
  color: string;
  size: number;
  ip: string;
  action: 'ALLOW' | 'BLOCK';
  isSpecial?: boolean;
  isExploding?: boolean;
  sparks?: Spark[];
  targetDestX?: number;
  targetDestY?: number;
  targetDestId?: string;
}

interface Spark {
  x: number;
  y: number;
  vx: number;
  vy: number;
  alpha: number;
  color: string;
}

interface TrafficNetworkCanvasProps {
  lastTriggerPkt: {
    ip: string;
    action: 'ALLOW' | 'BLOCK';
    time: number;
  } | null;
  compact?: boolean;
}

function TrafficNetworkCanvas({ lastTriggerPkt, compact }: TrafficNetworkCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<NetworkParticle[]>([]);
  const nextParticleId = useRef(0);
  const lastPktRef = useRef<typeof lastTriggerPkt>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.offsetWidth);
    let height = (canvas.height = canvas.offsetHeight);

    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.target === canvas) {
          const newWidth = canvas.offsetWidth;
          const newHeight = canvas.offsetHeight;
          if (canvas.width !== newWidth || canvas.height !== newHeight) {
            width = canvas.width = newWidth;
            height = canvas.height = newHeight;
          }
        }
      }
    });
    resizeObserver.observe(canvas);

    const spawnBackgroundParticle = () => {
      const marginX = width < 280 ? 40 : 60;
      const sourceNodes = [
        { id: 'src1', label: 'Internal LAN', sub: '192.168.1.10', x: marginX, y: height * 0.2, color: '#06b6d4' },
        { id: 'src2', label: 'External WAN', sub: '10.0.0.99', x: marginX, y: height * 0.4, color: '#f59e0b' },
        { id: 'src3', label: 'Cloud Server', sub: '172.16.0.1', x: marginX, y: height * 0.6, color: '#3b82f6' },
        { id: 'src4', label: 'IoT Gateway', sub: '192.168.10.2', x: marginX, y: height * 0.8, color: '#a855f7' }
      ];
      const src = sourceNodes[Math.floor(Math.random() * sourceNodes.length)];
      const id = nextParticleId.current++;
      const isBlock = Math.random() < 0.25;

      particlesRef.current.push({
        id,
        startX: src.x,
        startY: src.y,
        endX: width / 2,
        endY: height / 2,
        x: src.x,
        y: src.y,
        progress: 0,
        speed: 0.005 + Math.random() * 0.005,
        color: src.color,
        size: 2,
        ip: src.sub,
        action: isBlock ? 'BLOCK' : 'ALLOW'
      });
    };

    for (let i = 0; i < 5; i++) {
      spawnBackgroundParticle();
      particlesRef.current[i].progress = Math.random() * 0.7;
    }

    let spawnTimer = 0;

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      const marginX = width < 280 ? 40 : 60;
      const firewallNode = { x: width / 2, y: height / 2, label: 'FW SHIELD', r: 24 };
      
      const sourceNodes = [
        { id: 'src1', label: 'Internal LAN', sub: '192.168.1.10', x: marginX, y: height * 0.2, color: '#06b6d4' },
        { id: 'src2', label: 'External WAN', sub: '10.0.0.99', x: marginX, y: height * 0.4, color: '#f59e0b' },
        { id: 'src3', label: 'Cloud Server', sub: '172.16.0.1', x: marginX, y: height * 0.6, color: '#3b82f6' },
        { id: 'src4', label: 'IoT Gateway', sub: '192.168.10.2', x: marginX, y: height * 0.8, color: '#a855f7' }
      ];

      const destNodes = [
        { id: 'dst1', label: 'Trusted Local', x: width - marginX, y: height * 0.25, color: '#10b981' },
        { id: 'dst2', label: 'Web Server', x: width - marginX, y: height * 0.5, color: '#06b6d4' },
        { id: 'dst3', label: 'Audit Database', x: width - marginX, y: height * 0.75, color: '#8b5cf6' }
      ];

      const blockNode = { id: 'blocked', label: 'Blacklist Log', x: width / 2, y: height - 25, color: '#f43f5e' };

      // Draw background paths
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(30, 45, 84, 0.25)';
      
      sourceNodes.forEach(src => {
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.bezierCurveTo(src.x + 80, src.y, firewallNode.x - 80, firewallNode.y, firewallNode.x, firewallNode.y);
        ctx.stroke();
      });

      destNodes.forEach(dst => {
        ctx.beginPath();
        ctx.moveTo(firewallNode.x, firewallNode.y);
        ctx.bezierCurveTo(firewallNode.x + 80, firewallNode.y, dst.x - 80, dst.y, dst.x, dst.y);
        ctx.stroke();
      });

      ctx.beginPath();
      ctx.moveTo(firewallNode.x, firewallNode.y);
      ctx.lineTo(blockNode.x, blockNode.y);
      ctx.stroke();

      if (lastTriggerPkt && lastTriggerPkt !== lastPktRef.current) {
        lastPktRef.current = lastTriggerPkt;
        const matchedSrc = sourceNodes.find(s => s.sub === lastTriggerPkt.ip) || sourceNodes[0];
        
        particlesRef.current.push({
          id: nextParticleId.current++,
          startX: matchedSrc.x,
          startY: matchedSrc.y,
          endX: firewallNode.x,
          endY: firewallNode.y,
          x: matchedSrc.x,
          y: matchedSrc.y,
          progress: 0,
          speed: 0.012,
          color: '#00f2fe',
          size: 4.5,
          ip: lastTriggerPkt.ip,
          action: lastTriggerPkt.action,
          isSpecial: true
        });
      }

      spawnTimer++;
      if (spawnTimer > 40) {
        spawnBackgroundParticle();
        spawnTimer = 0;
      }

      particlesRef.current = particlesRef.current.filter(p => {
        if (p.isExploding) {
          if (!p.sparks || p.sparks.length === 0) return false;
          
          p.sparks.forEach(spark => {
            spark.x += spark.vx;
            spark.y += spark.vy;
            spark.vy += 0.04;
            spark.alpha -= 0.025;
            
            ctx.fillStyle = spark.color;
            ctx.globalAlpha = Math.max(0, spark.alpha);
            ctx.beginPath();
            ctx.arc(spark.x, spark.y, 1.5, 0, Math.PI * 2);
            ctx.fill();
          });
          
          p.sparks = p.sparks.filter(s => s.alpha > 0);
          ctx.globalAlpha = 1.0;
          return true;
        }

        const matchedSrc = sourceNodes.find(s => s.sub === p.ip) || sourceNodes[0];

        if (p.progress < 1.0) {
          p.progress += p.speed;
          if (p.progress > 1.0) p.progress = 1.0;

          const t = p.progress;
          const startX = matchedSrc.x;
          const startY = matchedSrc.y;
          const endX = firewallNode.x;
          const endY = firewallNode.y;

          const cp1x = startX + 60;
          const cp1y = startY;
          const cp2x = endX - 60;
          const cp2y = endY;
          
          p.x = (1 - t) ** 3 * startX + 3 * (1 - t) ** 2 * t * cp1x + 3 * (1 - t) * t ** 2 * cp2x + t ** 3 * endX;
          p.y = (1 - t) ** 3 * startY + 3 * (1 - t) ** 2 * t * cp1y + 3 * (1 - t) * t ** 2 * cp2y + t ** 3 * endY;
          
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.shadowBlur = p.isSpecial ? 15 : 0;
          ctx.shadowColor = p.color;
          ctx.fill();
          ctx.shadowBlur = 0;

          if (p.isSpecial) {
            ctx.font = '8px "Share Tech Mono"';
            ctx.fillStyle = '#f1f5f9';
            ctx.textAlign = 'center';
            ctx.fillText(`${p.ip} (SCANNING)`, p.x, p.y - 8);
          }
        } 
        else if (p.progress >= 1.0 && p.targetDestId === undefined) {
          if (p.action === 'BLOCK') {
            p.isExploding = true;
            p.sparks = [];
            for (let k = 0; k < 15; k++) {
              const angle = Math.random() * Math.PI * 2;
              const sp = 0.8 + Math.random() * 2.0;
              p.sparks.push({
                x: p.x,
                y: p.y,
                vx: Math.cos(angle) * sp,
                vy: Math.sin(angle) * sp,
                alpha: 1.0,
                color: '#f43f5e'
              });
            }
          } else {
            const randomDst = destNodes[Math.floor(Math.random() * destNodes.length)];
            p.targetDestId = randomDst.id;
            p.progress = 1.01;
            p.speed = 0.01;
            p.color = '#10b981';
          }
        } 
        else if (p.progress > 1.0) {
          const t = p.progress - 1.0;
          p.progress += p.speed;
          
          if (t >= 1.0) return false;

          const startX = firewallNode.x;
          const startY = firewallNode.y;
          
          let endX = destNodes[0].x;
          let endY = destNodes[0].y;
          if (p.targetDestId) {
            const matchedDst = destNodes.find(d => d.id === p.targetDestId);
            if (matchedDst) {
              endX = matchedDst.x;
              endY = matchedDst.y;
            }
          }

          const cp1x = startX + 60;
          const cp1y = startY;
          const cp2x = endX - 60;
          const cp2y = endY;

          p.x = (1 - t) ** 3 * startX + 3 * (1 - t) ** 2 * t * cp1x + 3 * (1 - t) * t ** 2 * cp2x + t ** 3 * endX;
          p.y = (1 - t) ** 3 * startY + 3 * (1 - t) ** 2 * t * cp1y + 3 * (1 - t) * t ** 2 * cp2y + t ** 3 * endY;

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.shadowBlur = p.isSpecial ? 15 : 0;
          ctx.shadowColor = p.color;
          ctx.fill();
          ctx.shadowBlur = 0;

          if (p.isSpecial) {
            ctx.font = '8px "Share Tech Mono"';
            ctx.fillStyle = '#10b981';
            ctx.textAlign = 'center';
            ctx.fillText('PASS', p.x, p.y - 8);
          }
        }

        return true;
      });

      // Draw source nodes
      sourceNodes.forEach(node => {
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1;
        ctx.beginPath();
        const pulse = 8 + Math.sin(Date.now() / 250) * 2;
        ctx.arc(node.x, node.y, pulse, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = '#030408';
        ctx.beginPath();
        ctx.arc(node.x, node.y, 6, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 3, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#f1f5f9';
        ctx.font = 'bold 8.5px "Space Grotesk"';
        ctx.textAlign = 'right';
        ctx.fillText(node.label, node.x - 12, node.y - 1);
        
        ctx.fillStyle = '#94a3b8';
        ctx.font = '7px "Share Tech Mono"';
        ctx.fillText(node.sub, node.x - 12, node.y + 8);
      });

      // Draw destination nodes
      destNodes.forEach(node => {
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1;
        ctx.beginPath();
        const pulse = 8 + Math.cos(Date.now() / 250) * 2;
        ctx.arc(node.x, node.y, pulse, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = '#030408';
        ctx.beginPath();
        ctx.arc(node.x, node.y, 6, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 3, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#f1f5f9';
        ctx.font = 'bold 8.5px "Space Grotesk"';
        ctx.textAlign = 'left';
        ctx.fillText(node.label, node.x + 12, node.y + 3);
      });

      // Draw blocked node
      ctx.strokeStyle = blockNode.color;
      ctx.lineWidth = 1;
      ctx.beginPath();
      const bPulse = 8 + Math.sin(Date.now() / 200) * 2;
      ctx.arc(blockNode.x, blockNode.y, bPulse, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = '#030408';
      ctx.beginPath();
      ctx.arc(blockNode.x, blockNode.y, 6, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = blockNode.color;
      ctx.beginPath();
      ctx.arc(blockNode.x, blockNode.y, 3, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = blockNode.color;
      ctx.font = 'bold 8.5px "Space Grotesk"';
      ctx.textAlign = 'center';
      ctx.fillText(blockNode.label, blockNode.x, blockNode.y + 14);

      // Draw Firewall Inspector
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(firewallNode.x, firewallNode.y, firewallNode.r, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = 'rgba(5, 7, 12, 0.95)';
      ctx.beginPath();
      ctx.arc(firewallNode.x, firewallNode.y, firewallNode.r - 2, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#06b6d4';
      ctx.font = 'bold 8.5px "Share Tech Mono"';
      ctx.textAlign = 'center';
      ctx.fillText('FW SHIELD', firewallNode.x, firewallNode.y - 2);
      ctx.fillStyle = '#10b981';
      ctx.font = 'bold 6.5px "Share Tech Mono"';
      ctx.fillText('INSPECTING', firewallNode.x, firewallNode.y + 6);

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      resizeObserver.disconnect();
      cancelAnimationFrame(animationFrameId);
    };
  }, [lastTriggerPkt]);

  return (
    <div className={`relative w-full ${compact ? 'h-[130px]' : 'h-[150px] md:h-[180px]'} bg-[#05070c]/50 rounded-xl overflow-hidden`}>
      <div className="absolute top-2 left-3 flex items-center gap-1.5 font-mono text-[9px] text-cyber-cyan uppercase tracking-wider">
        <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse"></span>
        Live Traffic Network Map
      </div>
      <canvas ref={canvasRef} className="w-full h-full" />
    </div>
  );
}

export default function App() {
  // Firewall State
  const [fw, setFw] = useState(() => {
    const f = new Firewall();
    f.loadDefaults();
    return f;
  });
  
  // React mirror states to trigger re-renders
  const [packets, setPackets] = useState<Packet[]>(() => fw.packetQueue.getElements());
  const [logs, setLogs] = useState<LogEntry[]>(() => fw.logManager.getLogs());
  const [bstIPs, setBstIPs] = useState<string[]>(() => fw.ipTree.getSortedBlockedIPs());
  const [heapRules, setHeapRules] = useState<Rule[]>(() => fw.ruleHeap.getRawArray());
  const [hashBuckets, setHashBuckets] = useState<{ index: number; chain: Rule[] }[]>(() => fw.ruleTable.getBuckets());
  const [stats, setStats] = useState(() => ({
    total: fw.totalProcessed,
    blocked: fw.logManager.getBlockedCount(),
    allowed: fw.logManager.getAllowedCount()
  }));
  const [activeTab, setActiveTab] = useState<'queue' | 'hash' | 'heap' | 'bst' | 'logs'>('queue');
  const activeTabRef = useRef(activeTab);
  useEffect(() => {
    activeTabRef.current = activeTab;
  }, [activeTab]);

  // Playback Control States for Stepper
  const [simpleMode, setSimpleMode] = useState(true); // Analogy mode toggle
  const [stepperSteps, setStepperSteps] = useState<StepperStep[]>([]);
  const [stepperIndex, setStepperIndex] = useState(0);
  const [isStepperActive, setIsStepperActive] = useState(false);
  const [isStepperPlaying, setIsStepperPlaying] = useState(false);
  const [stepperSpeed, setStepperSpeed] = useState(1000); // ms per step
  
  // Custom interactive test input states
  const [testBSTIP, setTestBSTIP] = useState('172.16.0.1');
  const [testHashIP, setTestHashIP] = useState('192.168.1.10');
  const [lastTriggerPkt, setLastTriggerPkt] = useState<{ ip: string; action: 'ALLOW' | 'BLOCK'; time: number } | null>(null);

  // UI state
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Stepper Playback Loop Effect
  useEffect(() => {
    if (!isStepperPlaying || !isStepperActive) return;
    const interval = setInterval(() => {
      setStepperIndex(prev => {
        if (prev < stepperSteps.length - 1) {
          const nextIdx = prev + 1;
          const nextStep = stepperSteps[nextIdx];
          if (nextStep && nextStep.tab !== activeTabRef.current) {
            setActiveTab(nextStep.tab);
          }
          return nextIdx;
        } else {
          setIsStepperPlaying(false);
          return prev;
        }
      });
    }, stepperSpeed);
    return () => clearInterval(interval);
  }, [isStepperPlaying, isStepperActive, stepperSteps, stepperSpeed]);

  // Sync state helper
  const getRenderState = () => {
    if (isStepperActive && stepperSteps[stepperIndex]) {
      const step = stepperSteps[stepperIndex];
      return {
        packets: step.stateSnapshot?.packets ?? packets,
        logs: step.stateSnapshot?.logs ?? logs,
        heapRules: step.stateSnapshot?.heapRules ?? heapRules,
        hashBuckets: step.stateSnapshot?.hashBuckets ?? hashBuckets,
        bstIPs: step.stateSnapshot?.bstIPs ?? bstIPs,
        highlights: step.highlights ?? {}
      };
    }
    return {
      packets,
      logs,
      heapRules,
      hashBuckets,
      bstIPs,
      highlights: {}
    };
  };

  const renderState = getRenderState();

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
    ruleID: 'R100',
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
  const syncStateWithInstance = (instance: Firewall) => {
    setPackets(instance.packetQueue.getElements());
    setLogs(instance.logManager.getLogs());
    setBstIPs(instance.ipTree.getSortedBlockedIPs());
    setHeapRules(instance.ruleHeap.getRawArray());
    setHashBuckets(instance.ruleTable.getBuckets());
    setStats({
      total: instance.totalProcessed,
      blocked: instance.logManager.getBlockedCount(),
      allowed: instance.logManager.getAllowedCount()
    });
  };

  const syncState = () => {
    syncStateWithInstance(fw);
  };

  // Handlers
  const handleLoadDefaults = () => {
    const newFw = new Firewall();
    newFw.loadDefaults();
    setFw(newFw);
    setStepResult(null);
    setSearchResults([]);
    setHasSearched(false);
    syncStateWithInstance(newFw);
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
      setLastTriggerPkt({
        ip: result.packet.sourceIP,
        action: result.decision.action === 'BLOCKED' ? 'BLOCK' : 'ALLOW',
        time: Date.now()
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
    const newFw = new Firewall();
    setFw(newFw);
    setStepResult(null);
    setSearchResults([]);
    setHasSearched(false);
    syncStateWithInstance(newFw);
  };

  const handleAddPacket = (e: React.FormEvent) => {
    e.preventDefault();
    const src = newPacket.sourceIP.trim();
    const dst = newPacket.destIP.trim();
    const port = Number(newPacket.port);
    const size = Number(newPacket.size);

    if (!src || !dst) {
      alert("Source and Destination IPs are required.");
      return;
    }
    if (!isValidIP(src)) {
      alert(`Invalid Source IP address format: "${src}". Please provide a valid IPv4 address (e.g., 192.168.1.10).`);
      return;
    }
    if (!isValidIP(dst)) {
      alert(`Invalid Destination IP address format: "${dst}". Please provide a valid IPv4 address (e.g., 10.0.0.99).`);
      return;
    }
    if (isNaN(port) || port < 1 || port > 65535) {
      alert("Invalid Port! Port must be a number between 1 and 65535.");
      return;
    }
    if (isNaN(size) || size <= 0) {
      alert("Invalid Packet Size! Size must be a positive number of bytes.");
      return;
    }

    const p = new Packet(src, dst, port, newPacket.protocol, size);
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

  // ============================================================
  //  DSA STEP-BY-STEP SIMULATION ANIMATORS
  // ============================================================

  const handleAnimateProcessPacket = () => {
    if (fw.packetQueue.empty()) {
      alert("No packets in the queue! Add a packet manually or reload defaults.");
      return;
    }
    
    const currentPackets = fw.packetQueue.getElements();
    const currentLogs = fw.logManager.getLogs();
    const currentHeapRules = fw.ruleHeap.getRawArray();
    const currentHashBuckets = fw.ruleTable.getBuckets();
    
    const steps: StepperStep[] = [];
    const pkt = fw.packetQueue.front()!;
    const srcIP = pkt.sourceIP;

    // Trigger visual particle on live network map
    const earlyMatchedRule = fw.ruleTable.search(srcIP);
    let finalAction: "ALLOW" | "BLOCK" = "ALLOW";
    if (earlyMatchedRule) {
      finalAction = earlyMatchedRule.action === "BLOCK" ? "BLOCK" : "ALLOW";
    } else {
      const bstRes = fw.ipTree.isBlocked(srcIP);
      if (bstRes) finalAction = "BLOCK";
    }
    setLastTriggerPkt({
      ip: srcIP,
      action: finalAction,
      time: Date.now()
    });
    
    // Step 0: Highlight front of queue
    steps.push({
      message: `[1/5] Queue Dequeue: Fetching packet at Front index ${fw.packetQueue.getFrontIdx()} (IP: ${srcIP}).`,
      simpleExplanation: `📮 Packet Arrived: We take the first packet waiting in our queue mailbox (from IP ${srcIP}) to inspect its contents.`,
      tab: 'queue',
      highlights: {
        activeQueueIdx: fw.packetQueue.getFrontIdx()
      },
      stateSnapshot: {
        packets: currentPackets,
        heapRules: currentHeapRules,
        hashBuckets: currentHashBuckets,
        logs: currentLogs
      }
    });

    // Step 1: Polynomial hash calculation steps
    const hashRes = fw.ruleTable.hashFunctionWithTrace(srcIP);
    steps.push({
      message: `[2/5] Hash Table Calculation: Hashing IP "${srcIP}". Index = sum(char * 31^i) % 101 = ${hashRes.finalIndex}.`,
      simpleExplanation: `🏷️ Generating Folder Label: We run a mathematical formula (hashing) on IP "${srcIP}" to calculate index ${hashRes.finalIndex}. This allows us to jump straight to this folder label instead of checking the whole database.`,
      tab: 'hash',
      highlights: {
        hashBucketIdx: hashRes.finalIndex
      },
      stateSnapshot: {
        packets: currentPackets,
        heapRules: currentHeapRules,
        hashBuckets: currentHashBuckets,
        logs: currentLogs
      }
    });

    // Step 2: HashTable collision chain check
    const searchRes = fw.ruleTable.searchWithTrace(srcIP);
    const matchedRule = searchRes.matchedRule;
    steps.push({
      message: matchedRule 
        ? `[3/5] Hash Match: Found exact match for "${srcIP}" in Bucket ${hashRes.finalIndex}. Rule ID: ${matchedRule.ruleID} (${matchedRule.action}).`
        : `[3/5] Hash Miss: IP "${srcIP}" not found in Bucket ${hashRes.finalIndex} chains. Checking BST...`,
      simpleExplanation: matchedRule 
        ? `✅ Exact Rule Found: We checked index folder ${hashRes.finalIndex} and found a direct rule matching "${srcIP}". This rule dictates that we ${matchedRule.action} the packet.`
        : `🔍 No Direct Rule: We checked index folder ${hashRes.finalIndex} and confirmed there is no specific VIP rule for "${srcIP}" here. Moving on to check our blacklist directory.`,
      tab: 'hash',
      highlights: {
        hashBucketIdx: hashRes.finalIndex,
        hashChainKeys: searchRes.checkedKeys,
        hashActiveKey: matchedRule?.targetIP
      },
      stateSnapshot: {
        packets: currentPackets,
        heapRules: currentHeapRules,
        hashBuckets: currentHashBuckets,
        logs: currentLogs
      }
    });

    let action: "ALLOW" | "BLOCK" | null = null;

    if (matchedRule) {
      action = matchedRule.action;
    }

    // Step 3: BST Check (if no hash match)
    if (action === null) {
      const bstRes = fw.ipTree.traceSearch(srcIP);
      steps.push({
        message: `[4/5] BST Search: Querying IP index tree for ranges. Visited: [${bstRes.path.join(' -> ')}].`,
        simpleExplanation: `🌳 Checking the Blocked Directory: We search a branching index tree. We compare "${srcIP}" to our nodes. Since it's sorted, we easily go left or right. Visited path: ${bstRes.path.join(' ➔ ') || 'none'}.`,
        tab: 'bst',
        highlights: {
          bstPath: bstRes.path,
          bstActiveNode: bstRes.path[bstRes.path.length - 1]
        },
        stateSnapshot: {
          packets: currentPackets,
          heapRules: currentHeapRules,
          hashBuckets: currentHashBuckets,
          logs: currentLogs
        }
      });

      if (bstRes.found) {
        action = "BLOCK";
        
        steps.push({
          message: `[4/5] BST Match: IP ${srcIP} matched inside Blocked IP tree. Action set to BLOCK (Priority 8).`,
          simpleExplanation: `🛑 Blacklist Match: We found IP "${srcIP}" listed inside our blocked IP tree. The firewall decides to BLOCK this packet.`,
          tab: 'bst',
          highlights: {
            bstPath: bstRes.path,
            bstActiveNode: srcIP
          },
          stateSnapshot: {
            packets: currentPackets,
            heapRules: currentHeapRules,
            hashBuckets: currentHashBuckets,
            logs: currentLogs
          }
        });
      } else {
        steps.push({
          message: `[4/5] BST Miss: IP ${srcIP} is not blacklisted in the BST index.`,
          simpleExplanation: `✅ Blacklist Clear: We checked the blacklist directory and found no entries matching "${srcIP}". The packet is clean so far.`,
          tab: 'bst',
          highlights: {
            bstPath: bstRes.path
          },
          stateSnapshot: {
            packets: currentPackets,
            heapRules: currentHeapRules,
            hashBuckets: currentHashBuckets,
            logs: currentLogs
          }
        });
      }
    }

    // Final Decision logic
    if (action === null) {
      // Default policy matches ALLOW
      
      steps.push({
        message: `[5/5] Default Policy: No blocking rules matched. Action set to ALLOW (Default).`,
        simpleExplanation: `🔓 Default Policy: No specific rules or blacklists matched this packet. By default, the firewall ALLOWS the packet to pass.`,
        tab: 'queue',
        highlights: {},
        stateSnapshot: {
          packets: currentPackets,
          heapRules: currentHeapRules,
          hashBuckets: currentHashBuckets,
          logs: currentLogs
        }
      });
    }

    // Process in the backend
    const processedRes = fw.processNext();
    if (processedRes) {
      const newPackets = fw.packetQueue.getElements();
      const newLogs = fw.logManager.getLogs();
      const dec = processedRes.decision.action;
      
      steps.push({
        message: `[Complete] Decision: ${dec}. Packet removed from queue front. Log entry added to log manager.`,
        simpleExplanation: `💾 Process Complete: The packet has been processed with the verdict: ${dec}. We removed it from the queue and logged this action.`,
        tab: 'logs',
        highlights: {},
        stateSnapshot: {
          packets: newPackets,
          heapRules: currentHeapRules,
          hashBuckets: currentHashBuckets,
          logs: newLogs
        }
      });
    }

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('queue');
  };

  const handleAnimateAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    const ruleID = newRule.ruleID.trim();
    const target = newRule.targetIP.trim();
    const priority = Number(newRule.priority);

    if (!ruleID) {
      alert("Rule ID is required.");
      return;
    }
    if (!target) {
      alert("IP Address is required.");
      return;
    }
    if (!isValidIP(target)) {
      alert(`Invalid Target IP address format: "${target}". Please provide a valid IPv4 address (e.g., 192.168.1.100).`);
      return;
    }
    if (isNaN(priority) || priority < 1 || priority > 10) {
      alert("Invalid Priority! Priority must be a number between 1 and 10.");
      return;
    }

    const rule = new Rule(
      ruleID,
      target,
      newRule.action,
      priority,
      newRule.protocol
    );

    // Rebuild copy of heap rule lists to trace heapify bubble-up
    const heapCopy = new MaxHeap();
    for (const r of fw.ruleHeap.getRawArray()) {
      heapCopy.push(r);
    }
    
    const traceSteps = heapCopy.pushWithTrace(rule);
    const steps: StepperStep[] = traceSteps.map((t: HeapTraceStep, idx: number) => ({
      message: `Heapify Bubble-Up (Step ${idx + 1}): ${t.message}`,
      simpleExplanation: `Bubble-Up (Step ${idx + 1}): ${getHeapSimpleExplanation(t.message)}`,
      tab: 'heap',
      highlights: {
        heapComparing: t.comparing || undefined,
        heapSwapping: t.swapping || undefined
      },
      stateSnapshot: {
        packets,
        heapRules: t.array,
        hashBuckets,
        logs
      }
    }));

    // Perform actual additions in backend
    fw.addRule(rule);
    syncState();

    steps.push({
      message: `Rule ${rule.ruleID} successfully added to HashTable and prioritized in Heap.`,
      simpleExplanation: `✅ Rule Added: Rule ${rule.ruleID} has been successfully added to our fast lookup database (Hash Table) and priority queue stack (Heap).`,
      tab: 'heap',
      highlights: {},
      stateSnapshot: {
        packets,
        heapRules: fw.ruleHeap.getRawArray(),
        hashBuckets: fw.ruleTable.getBuckets(),
        logs
      }
    });

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('heap');

    // regenerate ID
    setNewRule(prev => ({
      ...prev,
      ruleID: 'R' + String(Math.floor(Math.random() * 900) + 100)
    }));
  };

  const handleAnimatePopHeap = () => {
    if (fw.ruleHeap.empty()) {
      alert("Heap is empty!");
      return;
    }
    const heapCopy = new MaxHeap();
    for (const r of fw.ruleHeap.getRawArray()) {
      heapCopy.push(r);
    }
    
    const traceSteps = heapCopy.popWithTrace();
    const steps: StepperStep[] = traceSteps.map((t: HeapTraceStep, idx: number) => ({
      message: `Heapify Bubble-Down (Step ${idx + 1}): ${t.message}`,
      simpleExplanation: `Bubble-Down (Step ${idx + 1}): ${getHeapSimpleExplanation(t.message)}`,
      tab: 'heap',
      highlights: {
        heapComparing: t.comparing || undefined,
        heapSwapping: t.swapping || undefined
      },
      stateSnapshot: {
        packets,
        heapRules: t.array,
        hashBuckets,
        logs
      }
    }));

    fw.ruleHeap.pop();
    syncState();

    steps.push({
      message: `Root priority rule popped from Heap. Restructured rules.`,
      simpleExplanation: `🗑️ Root Rule Removed: We removed the highest priority rule from the top of the ladder and re-ordered the heap to find the next highest rule.`,
      tab: 'heap',
      highlights: {},
      stateSnapshot: {
        packets,
        heapRules: fw.ruleHeap.getRawArray(),
        hashBuckets,
        logs
      }
    });

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('heap');
  };

  const handleAnimateBSTSearch = (ip: string) => {
    const traceRes = fw.ipTree.traceSearch(ip);
    const steps: StepperStep[] = [];
    
    for (let i = 0; i < traceRes.path.length; i++) {
      const subPath = traceRes.path.slice(0, i + 1);
      const nodeIp = traceRes.path[i];
      let msg = `BST Traversal Step ${i + 1}: Checking node ${nodeIp}. `;
      let simpleMsg = `🌳 Checking blacklist directory: We compare "${ip}" to "${nodeIp}". `;
      if (ip === nodeIp) {
        msg += `MATCH found! The IP is blacklisted.`;
        simpleMsg += `Match found! This IP is blocked.`;
      } else if (ip < nodeIp) {
        msg += `"${ip}" < "${nodeIp}". Going LEFT.`;
        simpleMsg += `Since "${ip}" comes alphabetically before "${nodeIp}", we search in the left branch.`;
      } else {
        msg += `"${ip}" > "${nodeIp}". Going RIGHT.`;
        simpleMsg += `Since "${ip}" comes alphabetically after "${nodeIp}", we search in the right branch.`;
      }
      
      steps.push({
        message: msg,
        simpleExplanation: simpleMsg,
        tab: 'bst',
        highlights: {
          bstPath: subPath,
          bstActiveNode: nodeIp
        },
        stateSnapshot: {
          packets,
          heapRules,
          hashBuckets,
          logs
        }
      });
    }

    if (!traceRes.found) {
      steps.push({
        message: `Leaf reached. IP "${ip}" is NOT blocked in BST index.`,
        simpleExplanation: `✅ Checked: We reached the end of the blacklist directory and found no match. This IP is NOT blocked.`,
        tab: 'bst',
        highlights: {
          bstPath: traceRes.path
        },
        stateSnapshot: {
          packets,
          heapRules,
          hashBuckets,
          logs
        }
      });
    }

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('bst');
  };

  const handleAnimateHashTableSearch = (ip: string) => {
    const hashRes = fw.ruleTable.hashFunctionWithTrace(ip);
    const searchRes = fw.ruleTable.searchWithTrace(ip);
    const steps: StepperStep[] = [];
    
    // Hash calculations
    hashRes.steps.forEach((step) => {
      steps.push({
        message: `Polynomial Hash Calc (char ${step.char}): (CharCode ${step.charCode} - 32 + 1) * multiplier mod 101. Intermediate Hash index: ${step.intermediateHash}.`,
        simpleExplanation: `🏷️ Hashing Character: We take character "${step.char}" and calculate a running numerical code to build a unique address index: ${step.intermediateHash}.`,
        tab: 'hash',
        highlights: {
          hashBucketIdx: step.intermediateHash
        },
        stateSnapshot: {
          packets,
          heapRules,
          hashBuckets,
          logs
        }
      });
    });

    steps.push({
      message: `Calculated target Hash Bucket: Index ${hashRes.finalIndex}. Traversing collision linked chain...`,
      simpleExplanation: `📁 Target Folder Located: We determined that the rules for this IP would be stored in Folder Index ${hashRes.finalIndex}. Checking folder contents...`,
      tab: 'hash',
      highlights: {
        hashBucketIdx: hashRes.finalIndex
      },
      stateSnapshot: {
        packets,
        heapRules,
        hashBuckets,
        logs
      }
    });

    searchRes.checkedKeys.forEach((key, idx) => {
      const isMatch = key === ip;
      steps.push({
        message: `Checking Node ${idx + 1} key: "${key}". ${isMatch ? "MATCH found!" : "Key does not match. Checking next pointer."}`,
        simpleExplanation: `🔍 Inspecting Folder Node: We look at rule key "${key}". ${isMatch ? "MATCH! We found the exact rule for this IP." : "No match. Checking the next linked rule in this folder."}`,
        tab: 'hash',
        highlights: {
          hashBucketIdx: hashRes.finalIndex,
          hashChainKeys: searchRes.checkedKeys.slice(0, idx + 1),
          hashActiveKey: key
        },
        stateSnapshot: {
          packets,
          heapRules,
          hashBuckets,
          logs
        }
      });
    });

    if (!searchRes.matchedRule) {
      steps.push({
        message: `Null pointer reached. Rule not registered in Hash Table for IP ${ip}.`,
        simpleExplanation: `❌ End of Chain: We checked all rules in Folder Index ${hashRes.finalIndex} and found no rules matching "${ip}".`,
        tab: 'hash',
        highlights: {
          hashBucketIdx: hashRes.finalIndex,
          hashChainKeys: searchRes.checkedKeys
        },
        stateSnapshot: {
          packets,
          heapRules,
          hashBuckets,
          logs
        }
      });
    }

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('hash');
  };

  const handleAnimateSort = (type: 'time' | 'severity') => {
    if (logs.length === 0) {
      alert("No logs to sort! Process some packets first.");
      return;
    }
    if (logs.length > 15) {
      const proceed = window.confirm(
        `Warning: Animating step-by-step sorting on ${logs.length} logs will take a long time and might feel slow. \n\nClick OK to proceed with all logs, or Cancel to abort animation (you can still use the Instant Sort buttons).`
      );
      if (!proceed) return;
    }
    
    const sortSteps = type === 'time' 
      ? fw.logManager.sortByTimestampWithTrace() 
      : fw.logManager.sortBySeverityWithTrace();
    
    const steps: StepperStep[] = sortSteps.map((t: SortTraceStep, idx: number) => ({
      message: `Sorting iteration #${idx + 1}: ${t.message}`,
      simpleExplanation: `Sorting (Step ${idx + 1}): ${getSortSimpleExplanation(t.message)}`,
      tab: 'logs',
      highlights: {
        sortComparing: t.comparing || undefined,
        sortSwapping: t.swapping || undefined
      },
      stateSnapshot: {
        packets,
        heapRules,
        hashBuckets,
        logs: t.logs
      }
    }));

    if (type === 'time') {
      fw.logManager.sortByTimestamp();
    } else {
      fw.logManager.sortBySeverity();
    }
    syncState();

    steps.push({
      message: `Logs sorted using ${type === 'time' ? 'Quick Sort (O(n log n) by timestamp)' : 'Merge Sort (O(n log n) by priority)'}. comparisons: ${fw.logManager.sortMetrics.comparisons}, swaps: ${fw.logManager.sortMetrics.swaps}`,
      simpleExplanation: `✅ Logs Pre-sorted: All logs successfully sorted using ${type === 'time' ? 'Quick Sort (fast date order)' : 'Merge Sort (stable severity priority order)'}. comparisons: ${fw.logManager.sortMetrics.comparisons}, swaps: ${fw.logManager.sortMetrics.swaps}`,
      tab: 'logs',
      highlights: {},
      stateSnapshot: {
        packets,
        heapRules,
        hashBuckets,
        logs: fw.logManager.getLogs()
      }
    });

    setStepperSteps(steps);
    setStepperIndex(0);
    setIsStepperActive(true);
    setIsStepperPlaying(true);
    setActiveTab('logs');
  };


  // BST Tree Visualization layout
  const renderBSTNode = (node: BSTNode | null, x: number, y: number, dx: number): React.ReactNode[] => {
    if (!node) return [];
    const elements: React.ReactNode[] = [];
    
    const isPath = renderState.highlights.bstPath?.includes(node.ip);
    const isActiveNode = renderState.highlights.bstActiveNode === node.ip;
    
    let circleFill = "#11192e";
    let strokeColor = "#06b6d4";
    let circleClass = "transition-all duration-300 hover:fill-cyber-cardLight hover:stroke-cyber-emerald";
    
    if (isActiveNode) {
      circleFill = "#f59e0b";
      strokeColor = "#f59e0b";
      circleClass = "animate-pulse filter drop-shadow-[0_0_6px_rgba(245,158,11,0.8)]";
    } else if (isPath) {
      circleFill = "#1c3c6e";
      strokeColor = "#10b981";
    }

    if (node.left) {
      elements.push(
        <line 
          key={`line-l-${node.ip}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke={isPath && renderState.highlights.bstPath?.includes(node.left.ip) ? "#10b981" : "#1e2d54"} 
          strokeWidth="2"
        />
      );
      elements.push(...renderBSTNode(node.left, x - dx, y + 50, dx * 0.5));
    }
    if (node.right) {
      elements.push(
        <line 
          key={`line-r-${node.ip}`}
          x1={x} y1={y} x2={x + dx} y2={y + 50} 
          stroke={isPath && renderState.highlights.bstPath?.includes(node.right.ip) ? "#10b981" : "#1e2d54"} 
          strokeWidth="2"
        />
      );
      elements.push(...renderBSTNode(node.right, x + dx, y + 50, dx * 0.5));
    }
    
    elements.push(
      <g key={`node-${node.ip}`} className="group cursor-pointer">
        <circle 
          cx={x} cy={y} r="16" 
          fill={circleFill} stroke={strokeColor} strokeWidth="2" 
          className={circleClass}
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
    const activeHeapRules = renderState.heapRules;
    if (idx >= activeHeapRules.length) return [];
    const elements: React.ReactNode[] = [];
    const leftIdx = 2 * idx + 1;
    const rightIdx = 2 * idx + 2;
    const rule = activeHeapRules[idx];
    
    const isComparing = renderState.highlights.heapComparing?.includes(idx);
    const isSwapping = renderState.highlights.heapSwapping?.includes(idx);
    
    let circleFill = "#11192e";
    let strokeColor = rule.action === "BLOCK" ? "#f43f5e" : "#10b981";
    let circleClass = "transition-all duration-300 hover:fill-cyber-cardLight";
    
    if (isSwapping) {
      circleFill = "#f59e0b";
      strokeColor = "#f59e0b";
      circleClass = "animate-bounce filter drop-shadow-[0_0_6px_rgba(245,158,11,0.8)]";
    } else if (isComparing) {
      circleFill = "#1c3c6e";
      strokeColor = "#06b6d4";
    }
    
    if (leftIdx < activeHeapRules.length) {
      elements.push(
        <line 
          key={`h-line-l-${idx}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke={isComparing && renderState.highlights.heapComparing?.includes(leftIdx) ? "#06b6d4" : "#1e2d54"} 
          strokeWidth="2"
        />
      );
      elements.push(...renderHeapNode(leftIdx, x - dx, y + 50, dx * 0.5));
    }
    
    if (rightIdx < activeHeapRules.length) {
      elements.push(
        <line 
          key={`h-line-r-${idx}`}
          x1={x} y1={y} x2={x + dx} y2={y + 50} 
          stroke={isComparing && renderState.highlights.heapComparing?.includes(rightIdx) ? "#06b6d4" : "#1e2d54"} 
          strokeWidth="2"
        />
      );
      elements.push(...renderHeapNode(rightIdx, x + dx, y + 50, dx * 0.5));
    }
    
    elements.push(
      <g key={`h-node-${idx}`} className="group cursor-pointer">
        <circle 
          cx={x} cy={y} r="17" 
          fill={circleFill} 
          stroke={strokeColor} 
          strokeWidth="2" 
          className={circleClass}
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
    <div className="h-screen w-screen bg-cyber-darker text-cyber-text grid-bg relative overflow-hidden scanline flex flex-col">
      
      {/* GLOW DECORATIONS */}
      <div className="fixed top-[-10%] left-[-10%] w-[50%] h-[40%] bg-cyber-cyan/5 rounded-full blur-[120px] pointer-events-none z-0"></div>
      <div className="fixed bottom-[-10%] right-[-10%] w-[50%] h-[40%] bg-cyber-emerald/5 rounded-full blur-[120px] pointer-events-none z-0"></div>

      {/* HEADER */}
      <header className="border-b border-cyber-border/90 bg-[#02050c]/95 backdrop-blur-2xl sticky top-0 z-50 shadow-[0_12px_40px_-20px_rgba(0,0,0,0.75)]">
        <div className="max-w-7xl mx-auto px-5 py-4 flex flex-col lg:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-cyber-cyan/15 rounded-2xl border border-cyber-cyan/30 glow-cyan">
              <Shield className="w-6 h-6 text-cyber-cyan filter drop-shadow-[0_0_5px_rgba(6,182,212,0.5)]" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-lg font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-cyber-emerald font-sans">
                  FRMS CONTROL MAINBOARD
                </h1>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald font-mono text-[9px] uppercase tracking-wider animate-pulse">
                  <span className="w-1 h-1 rounded-full bg-cyber-emerald"></span>
                  SHIELD: ACTIVE
                </div>
              </div>
              <p className="text-[10px] text-cyber-textMuted font-mono uppercase tracking-widest mt-0.5">
                Firewall Rule Management & DSA Stepper Visualizer
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4 font-mono text-[11px] text-cyber-textMuted bg-[#0d1325]/80 px-4 py-2 rounded-full border border-cyber-border/50 shadow-[inset_0_0_0_1px_rgba(255,255,255,0.04)]">
            <span>Course: CSC211</span>
            <span className="text-cyber-border">|</span>
            <span>Team: Attaullah, Monis, Zeeshan</span>
          </div>
          <button onClick={() => setSidebarCollapsed(s => !s)} title="Toggle sidebar" aria-label="Toggle sidebar" className="ml-3 p-3 rounded-full bg-[#0d1426]/70 hover:bg-[#0d1426]/85 focus:outline-none border border-cyber-border/60">
            <ArrowRightLeft className={`w-5 h-5 transform ${sidebarCollapsed ? 'rotate-180' : ''}`} />
          </button>
        </div>
      </header>

      {/* MAIN WORKSPACE: SIDEBAR + VISUALIZATION */}
      <div className="flex flex-1 overflow-hidden relative z-10">

        {/* ═══════════ LEFT SIDEBAR ═══════════ */}
        <aside className={`${sidebarCollapsed ? 'w-16' : 'w-[360px]'} h-full flex-shrink-0 flex flex-col overflow-y-auto border-r border-cyber-border/60 bg-[#070913]/80 backdrop-blur transition-all duration-200`}> 

          {/* Compact collapsed sidebar */}
          {sidebarCollapsed && (
            <div className="flex flex-col items-center py-4 gap-3">
              <button onClick={() => setSidebarCollapsed(false)} title="Expand" aria-label="Expand sidebar" className="p-3 rounded-full bg-[#0d1426]/60 hover:bg-[#0d1426]/70 focus:outline-none">
                <ArrowRightLeft className="w-5 h-5 text-cyber-cyan" />
              </button>
              <div className="flex flex-col gap-3 mt-4">
                <button title="Load Defaults" aria-label="Load defaults" className="p-3 rounded hover:bg-[#0d1426]/50 focus:outline-none"><RefreshCw className="w-5 h-5 text-cyber-textMuted" /></button>
                <button title="Step Packet" aria-label="Step packet" className="p-3 rounded hover:bg-[#0d1426]/50 focus:outline-none"><Play className="w-5 h-5 text-cyber-textMuted" /></button>
                <button title="Animate Step" aria-label="Animate step" className="p-3 rounded hover:bg-[#0d1426]/50 focus:outline-none"><Activity className="w-5 h-5 text-cyber-textMuted" /></button>
                <button title="Process All" aria-label="Process all" className="p-3 rounded hover:bg-[#0d1426]/50 focus:outline-none"><PlayCircle className="w-5 h-5 text-cyber-textMuted" /></button>
                <button title="Reset" aria-label="Reset firewall" className="p-3 rounded hover:bg-[#0d1426]/50 focus:outline-none"><Trash2 className="w-5 h-5 text-cyber-textMuted" /></button>
              </div>
            </div>
          )}

          <div className={`${sidebarCollapsed ? 'hidden' : 'block'} w-full`}> 

          {/* STATS STRIP */}
          <div className="border-b border-cyber-border/40 p-4 flex-shrink-0 bg-[#020714]/85 backdrop-blur rounded-b-[2rem] shadow-inner shadow-cyber-border/10">
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase">Processed</div>
                <div className="text-lg font-bold font-mono text-cyber-cyan">{stats.total}<span className="text-[9px] text-cyber-textMuted ml-1">PKT</span></div>
              </div>
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase flex items-center gap-1"><ShieldAlert className="w-2.5 h-2.5 text-cyber-rose" />Blocked</div>
                <div className="text-lg font-bold font-mono text-cyber-rose">{stats.blocked}</div>
              </div>
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase flex items-center gap-1"><ShieldCheck className="w-2.5 h-2.5 text-cyber-emerald" />Allowed</div>
                <div className="text-lg font-bold font-mono text-cyber-emerald">{stats.allowed}</div>
              </div>
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase">Block Rate</div>
                <div className="text-lg font-bold font-mono text-cyber-amber">{blockRate}%</div>
              </div>
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase">Queue</div>
                <div className="text-lg font-bold font-mono text-cyber-text">{renderState.packets.length}<span className="text-[9px] text-cyber-textMuted ml-1">/{MAX_PACKETS}</span></div>
              </div>
              <div className="bg-[#0d1426]/60 border border-cyber-border/60 p-2 rounded-lg">
                <div className="text-[9px] font-mono text-cyber-textMuted uppercase">Rules</div>
                <div className="text-lg font-bold font-mono text-cyber-text">{renderState.heapRules.length}<span className="text-[9px] text-cyber-textMuted ml-1">/{MAX_RULES}</span></div>
              </div>
            </div>
          </div>

          {/* ACTION BUTTONS */}
          <div className="border-b border-cyber-border/40 p-3 flex-shrink-0">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-[9px] font-bold text-cyber-cyan uppercase tracking-wider">Inspection Engine</span>
              <span className="px-1.5 py-0.5 rounded text-[8px] bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald font-mono font-bold uppercase animate-pulse">● ACTIVE</span>
            </div>
            <div className="mb-3 rounded-2xl bg-[#06111e]/95 border border-cyber-border/60 p-3 text-[10px] text-cyber-textMuted font-mono leading-5">
              <div className="font-semibold text-cyber-cyan mb-1">Quick Tip</div>
              <p>Use the action buttons to process packets step-by-step or run the full firewall simulation. Collapse the sidebar to reveal more visualization space.</p>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <button onClick={handleLoadDefaults} aria-label="Load defaults" className="py-2.5 px-3 min-h-[44px] rounded-lg bg-cyber-card border border-cyber-border text-sm font-mono font-bold text-cyber-text hover:bg-cyber-cardLight hover:border-cyber-cyan/50 hover:text-cyber-cyan transition-all flex items-center justify-center gap-2 cursor-pointer">
                <RefreshCw className="w-4 h-4" /> Load Defaults
              </button>
              <button onClick={handleStepProcess} aria-label="Step packet" className="py-2.5 px-3 min-h-[44px] rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/35 text-cyber-cyan text-sm font-mono font-bold hover:bg-cyber-cyan/20 hover:border-cyber-cyan/60 transition-all flex items-center justify-center gap-2 cursor-pointer">
                <Play className="w-4 h-4 fill-cyber-cyan" /> Step Packet
              </button>
              <button onClick={handleAnimateProcessPacket} aria-label="Animate step" className="py-2.5 px-3 min-h-[44px] rounded-lg bg-cyber-emerald/10 border border-cyber-emerald/35 text-cyber-emerald text-sm font-mono font-bold hover:bg-cyber-emerald/20 hover:border-cyber-emerald/60 transition-all flex items-center justify-center gap-2 cursor-pointer">
                <Activity className="w-4 h-4 animate-pulse" /> Animate Step
              </button>
              <button onClick={handleProcessAll} aria-label="Process all" className="py-2.5 px-3 min-h-[44px] rounded-lg bg-gradient-to-r from-blue-600 to-cyber-cyan text-white text-sm font-mono font-bold hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer">
                <PlayCircle className="w-4 h-4" /> Process All
              </button>
              <button onClick={handleReset} aria-label="Reset firewall" className="col-span-2 py-2.5 rounded-lg min-h-[44px] bg-cyber-rose/10 border border-cyber-rose/35 text-cyber-rose text-sm font-mono font-bold hover:bg-cyber-rose/20 hover:border-cyber-rose/60 transition-all flex items-center justify-center gap-2 cursor-pointer">
                <Trash2 className="w-4 h-4" /> Reset Firewall
              </button>
            </div>
          </div>

          {/* SCROLLABLE FORMS AREA */}
          <div className="flex-1 overflow-y-auto p-3 space-y-4 scrollbar-thin">


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
            <div className="glass-panel p-5 rounded-2xl">
              <h2 className="text-xs font-bold font-mono tracking-wider text-cyber-cyan flex items-center gap-2 mb-4 uppercase">
                <Plus className="w-4 h-4 text-cyber-cyan" /> ADD FIREWALL RULE
              </h2>
              <form onSubmit={handleAnimateAddRule} className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Rule ID</label>
                    <input 
                      type="text" 
                      value={newRule.ruleID}
                      onChange={e => setNewRule(prev => ({ ...prev, ruleID: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan/25 transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Target IP</label>
                    <input 
                      type="text" 
                      value={newRule.targetIP}
                      onChange={e => setNewRule(prev => ({ ...prev, targetIP: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan/25 transition-all"
                      placeholder="192.168.1.100"
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Action</label>
                    <select 
                      value={newRule.action} 
                      onChange={e => setNewRule(prev => ({ ...prev, action: e.target.value as 'BLOCK' | 'ALLOW' }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan transition-all cursor-pointer"
                    >
                      <option value="BLOCK">BLOCK</option>
                      <option value="ALLOW">ALLOW</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Priority</label>
                    <input 
                      type="number" 
                      min="1" 
                      max="10" 
                      value={newRule.priority}
                      onChange={e => setNewRule(prev => ({ ...prev, priority: Number(e.target.value) }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Protocol</label>
                    <select 
                      value={newRule.protocol} 
                      onChange={e => setNewRule(prev => ({ ...prev, protocol: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-cyan transition-all cursor-pointer"
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
                  title="Insert this rule into the hash table and heap priority queue"
                  className="w-full mt-2.5 py-2 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/25 border border-cyber-cyan/35 text-cyber-cyan font-bold transition-all flex items-center justify-center gap-1.5 shadow"
                >
                  <Plus className="w-4 h-4" /> Insert to Table & Heap
                </button>
              </form>
            </div>

            {/* PACKET FORM */}
            <div className="glass-panel p-5 rounded-2xl">
              <h2 className="text-xs font-bold font-mono tracking-wider text-cyber-emerald flex items-center gap-2 mb-4 uppercase">
                <Plus className="w-4 h-4 text-cyber-emerald" /> QUEUE PACKET MANUALLY
              </h2>
              <form onSubmit={handleAddPacket} className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Source IP</label>
                    <input 
                      type="text" 
                      value={newPacket.sourceIP}
                      onChange={e => setNewPacket(prev => ({ ...prev, sourceIP: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald focus:ring-1 focus:ring-cyber-emerald/25 transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Dest IP</label>
                    <input 
                      type="text" 
                      value={newPacket.destIP}
                      onChange={e => setNewPacket(prev => ({ ...prev, destIP: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald focus:ring-1 focus:ring-cyber-emerald/25 transition-all"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Port</label>
                    <input 
                      type="number" 
                      value={newPacket.port}
                      onChange={e => setNewPacket(prev => ({ ...prev, port: Number(e.target.value) }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Protocol</label>
                    <select 
                      value={newPacket.protocol} 
                      onChange={e => setNewPacket(prev => ({ ...prev, protocol: e.target.value }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald transition-all cursor-pointer"
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="HTTP">HTTP</option>
                      <option value="ANY">ANY</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Size (B)</label>
                    <input 
                      type="number" 
                      value={newPacket.size}
                      onChange={e => setNewPacket(prev => ({ ...prev, size: Number(e.target.value) }))}
                      className="w-full bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-emerald transition-all"
                    />
                  </div>
                </div>

                <button 
                  type="submit" 
                  title="Queue a new packet for firewall processing"
                  className="w-full mt-2.5 py-2 rounded-lg bg-cyber-emerald/10 hover:bg-cyber-emerald/25 border border-cyber-emerald/35 text-cyber-emerald font-bold transition-all flex items-center justify-center gap-1.5 shadow"
                >
                  <Plus className="w-4 h-4" /> Push to Circular Queue
                </button>
              </form>
            </div>

            {/* LOG SEARCH BINARY SEARCH */}
            <div className="glass-panel p-5 rounded-2xl">
              <h2 className="text-xs font-bold font-mono tracking-wider text-cyber-amber flex items-center gap-2 mb-4 uppercase">
                <Search className="w-4 h-4 text-cyber-amber" /> BINARY SEARCH LOGS
              </h2>
              <form onSubmit={handleSearchLogs} className="space-y-3 font-mono text-xs">
                <div>
                  <label className="block text-[10px] text-cyber-textMuted uppercase mb-1">Search Source IP (Exact)</label>
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      value={searchIP}
                      onChange={e => setSearchIP(e.target.value)}
                      placeholder="e.g. 192.168.1.10"
                      className="flex-1 bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text focus:outline-none focus:border-cyber-amber focus:ring-1 focus:ring-cyber-amber/25 transition-all"
                    />
                    <button 
                      type="submit" 
                      title="Search logs by source IP address"
                      className="px-4 py-2 bg-cyber-amber/10 border border-cyber-amber/35 hover:bg-cyber-amber/25 text-cyber-amber font-bold rounded-lg transition-all flex items-center gap-1 shadow"
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
        </div>

          {/* MINI TRAFFIC CANVAS - ALWAYS VISIBLE AND STICKY */}
          {!sidebarCollapsed && (
            <div className="sticky top-0 z-20 border-b border-cyber-border/40 bg-[#070913]/95 p-3 flex-shrink-0 relative overflow-hidden backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-24 h-24 bg-cyber-cyan/5 rounded-full blur-2xl pointer-events-none"></div>
              <div className="relative z-10">
                <TrafficNetworkCanvas lastTriggerPkt={lastTriggerPkt} compact />
              </div>
            </div>
          )}
        </aside>
        {/* ═══ END LEFT SIDEBAR ═══ */}

        {/* ═══════════ RIGHT: VISUALIZATION PANEL ═══════════ */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* STEPPER PLAYBACK CONTROLLER */}
          {isStepperActive && stepperSteps.length > 0 && createPortal(
            <div className="fixed top-24 left-1/2 transform -translate-x-1/2 w-[95%] max-w-5xl z-[9999] bg-[#050b14]/95 backdrop-blur-xl border border-cyber-cyan/50 rounded-2xl px-5 py-4 shadow-[0_10px_40px_rgba(6,182,212,0.25)] overflow-hidden font-mono text-xs space-y-3 animate-fade-in">
              <div 
                className="absolute top-0 left-0 h-1 bg-cyber-cyan transition-all duration-300" 
                style={{ width: `${((stepperIndex + 1) / stepperSteps.length) * 100}%` }}
              ></div>
              
              <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-3">
                <div className="flex-1 space-y-1 w-full md:w-auto">
                  <div className="flex justify-between items-center text-[10px] text-cyber-cyan font-bold uppercase tracking-wider">
                    <span>Visual Simulation Active ({stepperSteps[stepperIndex].tab.toUpperCase()} Area)</span>
                    <span>Step {stepperIndex + 1} of {stepperSteps.length}</span>
                  </div>
                  <p className="text-cyber-text text-sm font-semibold leading-relaxed">
                    {simpleMode ? stepperSteps[stepperIndex].simpleExplanation : stepperSteps[stepperIndex].message}
                  </p>
                </div>
                <div className="flex items-center gap-3 bg-cyber-darker border border-cyber-border/60 px-3 py-1.5 rounded-lg flex-shrink-0">
                  <span className="text-[9px] text-cyber-textMuted font-bold uppercase tracking-wider">Analogy Mode</span>
                  <button
                    onClick={() => setSimpleMode(!simpleMode)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${simpleMode ? 'bg-cyber-cyan' : 'bg-cyber-border'}`}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-cyber-card transition-transform ${simpleMode ? 'translate-x-4.5' : 'translate-x-1'}`} />
                  </button>
                </div>
              </div>

              {/* Pipeline stages */}
              <div className="flex flex-wrap justify-between items-center text-center font-mono text-[9px] gap-1.5">
                {[
                  { label: '1. Queue Mailbox', tab: 'queue', desc: 'FIFO Buffer' },
                  { label: '2. Hash Check', tab: 'hash', desc: 'Fast Lookup' },
                  { label: '3. Blacklist BST', tab: 'bst', desc: 'Tree Search' },
                  { label: '4. Decision Log', tab: 'logs', desc: 'Record' }
                ].map((stage, i) => {
                  const stepTab = stepperSteps[stepperIndex].tab;
                  const isCurrent = stepTab === stage.tab;
                  let isActive = false;
                  if (stage.tab === 'queue' && (stepTab === 'queue' || stepTab === 'hash' || stepTab === 'bst' || stepTab === 'logs')) isActive = true;
                  if (stage.tab === 'hash' && (stepTab === 'hash' || stepTab === 'bst' || stepTab === 'logs' || stepTab === 'heap')) isActive = true;
                  if (stage.tab === 'bst' && (stepTab === 'bst' || stepTab === 'logs')) isActive = true;
                  if (stage.tab === 'logs' && stepTab === 'logs') isActive = true;
                  return (
                    <React.Fragment key={stage.label}>
                      <div className={`flex-1 min-w-[80px] p-1.5 rounded border transition-all duration-300 ${isCurrent ? 'bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan shadow-[0_0_8px_rgba(6,182,212,0.2)] font-bold' : isActive ? 'bg-cyber-border/20 border-cyber-border/40 text-cyber-text' : 'border-transparent text-cyber-textMuted/30'}`}>
                        <div className="uppercase tracking-wider font-semibold text-[8px]">{stage.label}</div>
                        <div className="text-[7px] opacity-70">{stage.desc}</div>
                      </div>
                      {i < 3 && <span className="text-cyber-border/40 hidden md:inline">➔</span>}
                    </React.Fragment>
                  );
                })}
              </div>

              <div className="flex flex-row justify-between items-center gap-3">
                <div className="flex flex-wrap gap-1.5">
                  <button onClick={() => { setStepperIndex(0); setIsStepperPlaying(false); }} disabled={stepperIndex === 0} className="px-2.5 py-1 rounded bg-cyber-border hover:bg-cyber-cardLight border border-cyber-border text-cyber-text text-[10px] font-bold disabled:opacity-40 transition">Reset</button>
                  <button onClick={() => { setStepperIndex(prev => Math.max(0, prev - 1)); setIsStepperPlaying(false); }} disabled={stepperIndex === 0} className="px-2.5 py-1 rounded bg-cyber-border hover:bg-cyber-cardLight border border-cyber-border text-cyber-text text-[10px] font-bold disabled:opacity-40 transition">◀ Prev</button>
                  <button onClick={() => setIsStepperPlaying(!isStepperPlaying)} className={`px-4 py-1 rounded font-bold text-[10px] transition ${isStepperPlaying ? 'bg-cyber-rose/20 text-cyber-rose border border-cyber-rose/40' : 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40'}`}>{isStepperPlaying ? '⏸ Pause' : '▶ Play'}</button>
                  <button onClick={() => { setStepperIndex(prev => Math.min(stepperSteps.length - 1, prev + 1)); setIsStepperPlaying(false); }} disabled={stepperIndex === stepperSteps.length - 1} className="px-2.5 py-1 rounded bg-cyber-border hover:bg-cyber-cardLight border border-cyber-border text-cyber-text text-[10px] font-bold disabled:opacity-40 transition">Next ▶</button>
                  <button onClick={() => { setIsStepperActive(false); setIsStepperPlaying(false); syncState(); }} className="px-2.5 py-1 rounded bg-cyber-rose/15 hover:bg-cyber-rose/30 border border-cyber-rose/40 text-cyber-rose text-[10px] font-bold transition">✕ Exit</button>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-[9px] text-cyber-textMuted font-bold uppercase">{stepperSpeed}ms</span>
                  <input type="range" min="200" max="2000" step="100" value={stepperSpeed} onChange={e => setStepperSpeed(Number(e.target.value))} className="w-24 h-1 bg-cyber-border rounded-lg appearance-none cursor-pointer accent-cyber-cyan" />
                </div>
              </div>
            </div>, document.body
          )}

          {/* TABBED VISUALIZATION */}
          <div className="flex flex-col flex-1 overflow-hidden glass-panel rounded-none border-0 border-l-0">  
            
            {/* TABS SELECTOR */}
            <div className="flex flex-wrap border-b border-cyber-border bg-[#030408]/45 font-mono text-xs">
              <button 
                onClick={() => setActiveTab('queue')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border/60 font-bold transition-all cursor-pointer ${activeTab === 'queue' ? 'bg-[#0d1426]/70 text-cyber-emerald border-t-2 border-t-cyber-emerald shadow-[inset_0_2px_8px_rgba(16,185,129,0.15)] glow-text-emerald' : 'text-cyber-textMuted hover:bg-[#0d1426]/30 hover:text-cyber-text'}`}
              >
                <Activity className="w-4 h-4" /> Queue Buffer
              </button>
              <button 
                onClick={() => setActiveTab('hash')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border/60 font-bold transition-all cursor-pointer ${activeTab === 'hash' ? 'bg-[#0d1426]/70 text-cyber-cyan border-t-2 border-t-cyber-cyan shadow-[inset_0_2px_8px_rgba(6,182,212,0.15)] glow-text-cyan' : 'text-cyber-textMuted hover:bg-[#0d1426]/30 hover:text-cyber-text'}`}
              >
                <Database className="w-4 h-4" /> Hash Table (Rules)
              </button>
              <button 
                onClick={() => setActiveTab('heap')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border/60 font-bold transition-all cursor-pointer ${activeTab === 'heap' ? 'bg-[#0d1426]/70 text-cyber-rose border-t-2 border-t-cyber-rose shadow-[inset_0_2px_8px_rgba(244,63,94,0.15)] glow-text-rose' : 'text-cyber-textMuted hover:bg-[#0d1426]/30 hover:text-cyber-text'}`}
              >
                <Flame className="w-4 h-4" /> Max-Heap (Priorities)
              </button>
              <button 
                onClick={() => setActiveTab('bst')}
                className={`flex items-center gap-1.5 px-4 py-3 border-r border-cyber-border/60 font-bold transition-all cursor-pointer ${activeTab === 'bst' ? 'bg-[#0d1426]/70 text-cyber-cyan border-t-2 border-t-cyber-cyan shadow-[inset_0_2px_8px_rgba(6,182,212,0.15)] glow-text-cyan' : 'text-cyber-textMuted hover:bg-[#0d1426]/30 hover:text-cyber-text'}`}
              >
                <Network className="w-4 h-4" /> BST (Blocked IPs)
              </button>
              <button 
                onClick={() => setActiveTab('logs')}
                className={`flex items-center gap-1.5 px-4 py-3 font-bold transition-all cursor-pointer ${activeTab === 'logs' ? 'bg-[#0d1426]/70 text-cyber-amber border-t-2 border-t-cyber-amber shadow-[inset_0_2px_8px_rgba(245,158,11,0.15)]' : 'text-cyber-textMuted hover:bg-[#0d1426]/30 hover:text-cyber-text'}`}
              >
                <Clock className="w-4 h-4" /> Sorting & Logs
              </button>
            </div>

            {/* TAB CONTENTS */}
            <div className={`p-6 flex-1 flex flex-col overflow-y-auto min-h-0 relative ${isStepperActive ? 'pt-32' : ''}`}>
              
              {/* TAB 1: PACKET QUEUE */}
              {activeTab === 'queue' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div className="space-y-2">
                    <div>
                      <h3 className="text-sm font-bold font-mono text-cyber-emerald uppercase tracking-wider mb-1">Packet Processing Queue (FIFO circular array)</h3>
                      <p className="text-xs text-cyber-textMuted font-mono">
                        Packets arrive in circular buffer. First in, first out. Drag/slide to view indices. Next item to process is shown at index <span className="text-cyber-emerald font-bold">{fw.packetQueue.getFrontIdx()}</span>.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="bg-cyber-emerald/5 border border-cyber-emerald/30 p-3 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                        <div className="p-1.5 bg-cyber-emerald/10 rounded text-cyber-emerald font-bold flex-shrink-0">💡 Analogy</div>
                        <div>
                          <span className="text-cyber-text font-semibold">Circular Queue (Conveyor Belt):</span> Like a round conveyor belt of suitcases at airport luggage claim. Packets are handled in the exact order they arrive (First-In, First-Out).
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {renderState.packets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      <AlertTriangle className="w-8 h-8 text-cyber-amber mb-2" />
                      Queue is currently empty! Add packets or load defaults above.
                    </div>
                  ) : (
                    <div className="space-y-6 flex-1 flex flex-col justify-center">
                      
                      {/* FIFO CONVEYOR VIEW */}
                      <div className="flex items-center justify-center p-4 bg-[#030408]/45 border border-cyber-border/70 rounded-2xl gap-2 overflow-x-auto select-none py-8">
                        {renderState.packets.map((pkt, idx) => {
                          const isActive = renderState.highlights.activeQueueIdx !== undefined && idx === 0;
                          return (
                            <React.Fragment key={`conveyor-${idx}`}>
                              {idx > 0 && <span className="text-cyber-border/70 font-bold">➔</span>}
                              <div className={`flex-shrink-0 w-[140px] bg-[#0d1426]/75 border p-3.5 rounded-xl font-mono text-[10px] space-y-1 relative transition-all duration-300 shadow ${isActive ? 'border-cyber-cyan bg-cyber-cyan/15 scale-105 glow-cyan' : idx === 0 ? 'border-cyber-emerald bg-cyber-emerald/10 glow-emerald' : 'border-cyber-border/80'}`}>
                                {idx === 0 && (
                                  <span className={`absolute top-[-8px] right-2 px-1 rounded text-[7px] font-bold uppercase tracking-wider ${isActive ? 'bg-cyber-cyan text-cyber-darker' : 'bg-cyber-emerald text-cyber-darker'}`}>{isActive ? 'PROCESSING' : 'NEXT'}</span>
                                )}
                                <div className="font-bold text-cyber-text truncate">{pkt.sourceIP}</div>
                                <div className="text-cyber-textMuted truncate">→ {pkt.destIP}</div>
                                <div className="text-cyber-cyan">Port: {pkt.port}</div>
                                <div className="text-cyber-textMuted">Proto: {pkt.protocol}</div>
                                <div className="text-cyber-textMuted">Size: {pkt.size}B</div>
                              </div>
                            </React.Fragment>
                          );
                        })}
                      </div>

                      {/* RAW CIRCULAR ARRAY VIEW */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-xs font-bold font-mono text-cyber-textMuted">Circular Array Buffer Index Diagram (Cap: {MAX_PACKETS})</span>
                          <div className="flex gap-4 font-mono text-[10px]">
                            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-cyber-emerald rounded"></span> Front ({fw.packetQueue.getFrontIdx()})</span>
                            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-blue-500 rounded"></span> Rear ({fw.packetQueue.getRearIdx()})</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-8 sm:grid-cols-12 gap-1.5 font-mono text-center">
                          {Array.from({ length: MAX_PACKETS }).map((_, idx) => {
                            const rawArray = fw.packetQueue.getRawArray();
                            const hasP = rawArray[idx] !== null;
                            const isFront = idx === fw.packetQueue.getFrontIdx();
                            const isRear = idx === fw.packetQueue.getRearIdx();
                            
                            let bgClass = "bg-cyber-card/40 border-cyber-border/40 text-cyber-textMuted";
                            if (hasP) bgClass = "bg-cyber-card border-cyber-border text-cyber-text";
                            if (isFront) bgClass = "bg-cyber-emerald/10 border-cyber-emerald text-cyber-emerald font-bold";
                            if (isRear) bgClass = "bg-blue-950/20 border-blue-500 text-blue-400 font-bold";
                            
                            if (renderState.highlights.activeQueueIdx === idx) {
                              bgClass = "bg-cyber-cyan/20 border-cyber-cyan text-cyber-cyan font-bold animate-pulse";
                            }

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
                            *Showing all {MAX_PACKETS} slots of the circular queue buffer.
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
                  <div className="space-y-2">
                    <div>
                      <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-1">Rule Lookup Hash Table (Polynomial Chaining)</h3>
                      <p className="text-xs text-cyber-textMuted font-mono">
                        Rules are inserted using polynomial rolling hash `H(IP) = Σ (c_i * 31^i) % 101`. Collisions prepended to linked chains.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="bg-cyber-cyan/5 border border-cyber-cyan/30 p-3 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                        <div className="p-1.5 bg-cyber-cyan/10 rounded text-cyber-cyan font-bold flex-shrink-0">💡 Analogy</div>
                        <div>
                          <span className="text-cyber-text font-semibold">Hash Table (VIP Filing Cabinet):</span> Like a filing cabinet with labeled folders. Instead of looking through every single rule, we calculate a label for the IP address and look *directly* into that folder. If multiple rules share the same folder, we file them one after the other in a list (Chaining).
                        </div>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE HASH TESTER */}
                  <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
                    <div className="space-y-1">
                      <h4 className="font-bold text-cyber-cyan uppercase">Interactive Hash Calculation Tester</h4>
                      <p className="text-cyber-textMuted text-[10px]">Enter an IP to step through the rolling polynomial hash calculation and see collision scan.</p>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={testHashIP}
                        onChange={e => setTestHashIP(e.target.value)}
                        className="bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text font-mono text-xs focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan/25 w-40 transition-all"
                      />
                      <button
                        onClick={() => handleAnimateHashTableSearch(testHashIP)}
                        className="px-3 py-2 bg-cyber-cyan/10 hover:bg-cyber-cyan/25 border border-cyber-cyan/35 text-cyber-cyan font-mono font-bold rounded-lg shadow transition-all cursor-pointer"
                      >
                        Animate Hash Lookup
                      </button>
                    </div>
                  </div>
                  
                  {renderState.hashBuckets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No rules loaded! Load default configurations.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* BUCKET SCROLL GRID */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col max-h-[400px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan mb-3">Active Hash Buckets (Size: {HASH_TABLE_SIZE})</h4>
                        <div className="flex-1 overflow-y-auto space-y-2.5 pr-2">
                          {renderState.hashBuckets.map((bucket) => {
                            const isBucketActive = renderState.highlights.hashBucketIdx === bucket.index;
                            return (
                              <div 
                                key={`bucket-${bucket.index}`} 
                                className={`bg-cyber-card border rounded p-2.5 font-mono text-xs flex items-center justify-between transition-all duration-300 ${isBucketActive ? 'border-cyber-cyan bg-cyber-cyan/10 shadow-[0_0_8px_rgba(6,182,212,0.3)] scale-[1.01]' : 'border-cyber-border'}`}
                              >
                                <div className="flex items-center gap-3">
                                  <span className={`px-2 py-0.5 border text-[10px] rounded font-bold ${isBucketActive ? 'bg-cyber-cyan text-cyber-darker border-cyber-cyan' : 'bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan'}`}>
                                    Bucket {bucket.index}
                                  </span>
                                  <span className="text-cyber-textMuted text-[10px]">
                                    Chain length: {bucket.chain.length}
                                  </span>
                                </div>
                                <div className="flex items-center gap-1 overflow-x-auto max-w-[200px]">
                                  {bucket.chain.map((rule, idx) => {
                                    const isKeyChecked = renderState.highlights.hashChainKeys?.includes(rule.targetIP);
                                    const isKeyActive = renderState.highlights.hashActiveKey === rule.targetIP;
                                    
                                    let ruleClass = rule.action === "BLOCK" ? "bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/20" : "bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/20";
                                    if (isKeyActive) {
                                      ruleClass = "bg-cyber-amber text-cyber-darker border border-cyber-amber font-extrabold animate-pulse scale-105";
                                    } else if (isKeyChecked) {
                                      ruleClass = "bg-cyber-cyan/25 text-cyber-cyan border border-cyber-cyan/40";
                                    }

                                    return (
                                      <span 
                                        key={`chain-${bucket.index}-${idx}`}
                                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold transition-all ${ruleClass}`}
                                        title={`Rule: ${rule.ruleID}\nIP: ${rule.targetIP}\nPriority: ${rule.priority}`}
                                      >
                                        {rule.ruleID}
                                      </span>
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
 
                      {/* DETAILED ACTIVE RULES LIST */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col max-h-[400px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-3">All Active Rules ({renderState.heapRules.length})</h4>
                        <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                          {renderState.heapRules.map((rule) => (
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
                  <div className="space-y-2">
                    <div>
                      <h3 className="text-sm font-bold font-mono text-cyber-rose uppercase tracking-wider mb-1">Priority Rule Max-Heap (Array Index Hierarchy)</h3>
                      <p className="text-xs text-cyber-textMuted font-mono">
                        Rules organized by priority. Highest priority rule is always at root (index 0). Children indices calculated as `left = 2*i + 1`, `right = 2*i + 2`.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="bg-cyber-rose/5 border border-cyber-rose/30 p-3 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                        <div className="p-1.5 bg-cyber-rose/10 rounded text-cyber-rose font-bold flex-shrink-0">💡 Analogy</div>
                        <div>
                          <span className="text-cyber-text font-semibold">Priority Heap (Urgency Stack):</span> Like sorting hospital patients in an emergency room by severity. The most urgent rule (highest priority) is always placed right at the top (root). When the top rule is removed or a new one is added, rules bubble up or bubble down until the most urgent rule is back on top.
                        </div>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE HEAP CONTROLS */}
                  <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
                    <div className="space-y-1">
                      <h4 className="font-bold text-cyber-rose uppercase">Interactive Heap Dequeue</h4>
                      <p className="text-cyber-textMuted text-[10px]">Pop the root of the Priority Queue Max-Heap to watch step-by-step visual heapify-down restructuring.</p>
                    </div>
                    <button
                      onClick={handleAnimatePopHeap}
                      disabled={renderState.heapRules.length === 0}
                      className="px-3.5 py-2 bg-cyber-rose/10 hover:bg-cyber-rose/25 border border-cyber-rose/35 text-cyber-rose font-mono font-bold rounded-lg shadow disabled:opacity-40 transition-all cursor-pointer"
                    >
                      Animate Pop Root (Priority-Extract)
                    </button>
                  </div>
                  
                  {renderState.heapRules.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No rules loaded! Load defaults above.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE RENDER CONTAINER */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col items-center justify-center min-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-rose self-start mb-4">Max-Heap Binary Tree Layout</h4>
                        <div className="w-full flex justify-center overflow-x-auto overflow-y-hidden">
                          <svg viewBox="0 0 600 280" className="w-full max-w-[600px] h-auto flex-shrink-0">
                            {renderHeapNode(0, 300, 30, 130)}
                          </svg>
                        </div>
                      </div>

                      {/* HEAP ARRAY FLAT VIEW */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col">
                        <h4 className="text-xs font-bold font-mono text-cyber-textMuted mb-3">Flat Max-Heap Array Memory Representation</h4>
                        <div className="grid grid-cols-5 gap-2 font-mono text-center overflow-y-auto max-h-[300px] pr-1">
                          {renderState.heapRules.map((rule, idx) => {
                            const isComparing = renderState.highlights.heapComparing?.includes(idx);
                            const isSwapping = renderState.highlights.heapSwapping?.includes(idx);
                            let itemBg = idx === 0 ? 'bg-cyber-rose/10 border-cyber-rose text-cyber-rose' : 'bg-cyber-card border-cyber-border';
                            
                            if (isSwapping) {
                              itemBg = "bg-cyber-amber text-cyber-darker border border-cyber-amber font-bold animate-pulse";
                            } else if (isComparing) {
                              itemBg = "bg-cyber-cyan/20 border-cyber-cyan text-cyber-cyan font-bold";
                            }

                            return (
                              <div 
                                key={`flat-heap-${idx}`} 
                                className={`border rounded p-1.5 text-[10px] space-y-1 relative flex flex-col justify-between transition-all duration-300 ${itemBg}`}
                              >
                                <span className="text-[7.5px] text-cyber-textMuted absolute top-0.5 left-1">#{idx}</span>
                                <div className="font-bold pt-2">{rule.ruleID}</div>
                                <div className="text-[8.5px] font-bold">Pri: {rule.priority}</div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: BST */}
              {activeTab === 'bst' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div className="space-y-2">
                    <div>
                      <h3 className="text-sm font-bold font-mono text-cyber-cyan uppercase tracking-wider mb-1">Blocked IPs Range BST (Binary Search Tree)</h3>
                      <p className="text-xs text-cyber-textMuted font-mono">
                        Stores blocked rule IP addresses in sorted order. Fast `O(log n)` check if an arriving packet IP is blacklisted.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="bg-cyber-cyan/5 border border-cyber-cyan/30 p-3 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                        <div className="p-1.5 bg-cyber-cyan/10 rounded text-cyber-cyan font-bold flex-shrink-0">💡 Analogy</div>
                        <div>
                          <span className="text-cyber-text font-semibold">Binary Search Tree (Alphabetical Phonebook):</span> Like finding a name in a phonebook by opening to the middle. If the target name is alphabetically earlier, you search only the left half; if later, only the right half. This repeatedly cuts the search area in half, making search extremely fast.
                        </div>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE BST TESTER */}
                  <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
                    <div className="space-y-1">
                      <h4 className="font-bold text-cyber-cyan uppercase font-mono">Interactive BST Path Tester</h4>
                      <p className="text-cyber-textMuted text-[10px]">Enter an IP address to watch the step-by-step tree comparison path search traversal.</p>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={testBSTIP}
                        onChange={e => setTestBSTIP(e.target.value)}
                        className="bg-[#030408]/65 border border-cyber-border/80 p-2 rounded text-cyber-text font-mono text-xs focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan/25 w-40 transition-all"
                      />
                      <button
                        onClick={() => handleAnimateBSTSearch(testBSTIP)}
                        className="px-3 py-2 bg-cyber-cyan/10 hover:bg-cyber-cyan/25 border border-cyber-cyan/35 text-cyber-cyan font-mono font-bold rounded-lg shadow transition-all cursor-pointer"
                      >
                        Animate Search
                      </button>
                    </div>
                  </div>
                  
                  {renderState.bstIPs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No blocked rules are active! Insert a BLOCK rule.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE SVG DIAGRAM */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col items-center justify-center min-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan self-start mb-4">BST Block Index Visualizer</h4>
                        <div className="w-full flex justify-center overflow-x-auto overflow-y-hidden">
                          <svg viewBox="0 0 600 280" className="w-full max-w-[600px] h-auto flex-shrink-0">
                            {renderBSTNode(fw.ipTree.getRoot(), 300, 30, 130)}
                          </svg>
                        </div>
                      </div>

                      {/* IN-ORDER SORTED LIST */}
                      <div className="bg-[#030408]/45 border border-cyber-border/70 rounded-2xl p-4 flex flex-col max-h-[300px]">
                        <h4 className="text-xs font-bold font-mono text-cyber-cyan mb-3">Sorted IP Blocking Index (BST In-Order)</h4>
                        <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                          {renderState.bstIPs.map((ip, idx) => {
                            const isActiveNode = renderState.highlights.bstActiveNode === ip;
                            const isPath = renderState.highlights.bstPath?.includes(ip);
                            let ipClass = "bg-cyber-card border-cyber-border";
                            
                            if (isActiveNode) {
                              ipClass = "bg-cyber-amber text-cyber-darker border border-cyber-amber font-extrabold animate-pulse scale-[1.02] shadow-[0_0_6px_rgba(245,158,11,0.4)]";
                            } else if (isPath) {
                              ipClass = "bg-cyber-cyan/20 border-cyber-cyan text-cyber-cyan";
                            }

                            return (
                              <div key={`bst-ip-${idx}`} className={`rounded p-2 font-mono text-xs flex justify-between items-center transition-all ${ipClass}`}>
                                <div className="flex items-center gap-2">
                                  <span className="text-[10px] text-cyber-textMuted">#{idx + 1}</span>
                                  <span className={`font-bold ${isActiveNode ? 'text-cyber-darker' : isPath ? 'text-cyber-cyan' : 'text-cyber-rose'}`}>{ip}</span>
                                </div>
                                <span className={`text-[10px] ${isActiveNode ? 'text-cyber-darker font-bold' : 'text-cyber-textMuted'}`}>Lexicographical sort</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: LOGS & SORTING */}
              {activeTab === 'logs' && (
                <div className="space-y-6 flex-1 flex flex-col">
                  <div className="space-y-2">
                    <div>
                      <h3 className="text-sm font-bold font-mono text-cyber-amber uppercase tracking-wider mb-1">Logs Manager & Sorting Visualizer</h3>
                      <p className="text-xs text-cyber-textMuted font-mono">
                        Compare Quick Sort vs Merge Sort on live firewall log data. Watch the sorting algorithm animate step-by-step.
                      </p>
                    </div>
                    {simpleMode && (
                      <div className="bg-cyber-amber/5 border border-cyber-amber/30 p-3 rounded-lg flex items-start gap-2.5 font-mono text-xs">
                        <div className="p-1.5 bg-cyber-amber/10 rounded text-cyber-amber font-bold flex-shrink-0">💡 Analogy</div>
                        <div>
                          <span className="text-cyber-text font-semibold">Sorting (Organizing Filing Cards):</span>
                          <ul className="list-disc list-inside mt-1 space-y-1 pl-1">
                            <li><span className="font-semibold text-cyber-cyan">Quick Sort (Filing by Pivot):</span> Pick a card as a "pivot", put all earlier cards to the left and all later cards to the right, then repeat this for each side.</li>
                            <li><span className="font-semibold text-cyber-amber">Merge Sort (Divide & Combine):</span> Split the deck of cards in halves until you have individual cards, then merge them back together in perfect sorted order.</li>
                          </ul>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* SORT CONTROLS & METRICS */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#030408]/45 border border-cyber-border/70 p-4 rounded-2xl">
                    <div className="space-y-3">
                      <h4 className="text-xs font-bold font-mono text-cyber-textMuted uppercase">Sort Operations</h4>
                      <div className="flex flex-wrap gap-2.5">
                        <button 
                          onClick={() => handleSortLogs('time')}
                          className="px-3.5 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-[11px] font-mono font-bold text-cyber-text hover:bg-[#0d1426]/60 hover:text-cyber-cyan hover:border-cyber-cyan/50 transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <Clock className="w-3.5 h-3.5" /> Instant Quick Sort
                        </button>
                        <button 
                          onClick={() => handleAnimateSort('time')}
                          className="px-3.5 py-1.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/25 border border-cyber-cyan/35 text-cyber-cyan font-mono font-bold text-[11px] transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <Activity className="w-3.5 h-3.5 text-cyber-cyan animate-pulse" /> Animate Quick Sort
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-2.5">
                        <button 
                          onClick={() => handleSortLogs('severity')}
                          className="px-3.5 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-[11px] font-mono font-bold text-cyber-text hover:bg-[#0d1426]/60 hover:text-cyber-amber hover:border-cyber-amber/50 transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <ArrowRightLeft className="w-3.5 h-3.5" /> Instant Merge Sort
                        </button>
                        <button 
                          onClick={() => handleAnimateSort('severity')}
                          className="px-3.5 py-1.5 rounded-lg bg-cyber-amber/10 hover:bg-cyber-amber/25 border border-cyber-amber/35 text-cyber-amber font-mono font-bold text-[11px] transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <Activity className="w-3.5 h-3.5 text-cyber-amber animate-pulse" /> Animate Merge Sort
                        </button>
                      </div>
                    </div>

                    <div className="bg-[#030408]/65 border border-cyber-border/80 rounded-xl p-3.5 font-mono text-[11px] space-y-1.5">
                      <div className="text-cyber-textMuted font-bold border-b border-cyber-border/40 pb-1 mb-1.5 uppercase">Algorithm Benchmark Statistics</div>
                      <div className="flex justify-between"><span>Comparisons:</span><span className="text-cyber-cyan font-bold">{fw.logManager.sortMetrics.comparisons}</span></div>
                      <div className="flex justify-between"><span>Array Writes/Swaps:</span><span className="text-cyber-cyan font-bold">{fw.logManager.sortMetrics.swaps}</span></div>
                      <div className="flex justify-between"><span>Time Taken:</span><span className="text-cyber-emerald font-bold">{fw.logManager.sortMetrics.timeTakenMs} ms</span></div>
                    </div>
                  </div>

                  {/* LOGS TABLE */}
                  {renderState.logs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-cyber-border rounded-xl p-8 font-mono text-xs text-cyber-textMuted italic">
                      No logs recorded yet. Start processing packets!
                    </div>
                  ) : (
                    <div className="border border-cyber-border/80 rounded-2xl overflow-hidden flex-1 max-h-[350px] overflow-y-auto shadow-inner bg-[#030408]/45">
                      <table className="w-full text-left font-mono text-xs border-collapse">
                        <thead className="bg-[#030408]/90 text-cyber-textMuted border-b border-cyber-border/80 sticky top-0">
                          <tr>
                            <th className="p-3">Index</th>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3">Action</th>
                            <th className="p-3">Source IP</th>
                            <th className="p-3">Port</th>
                            <th className="p-3">Matched Rule</th>
                            <th className="p-3 text-right">Pri</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-cyber-border/40">
                          {renderState.logs.map((log, idx) => {
                            const isComparing = renderState.highlights.sortComparing?.includes(idx);
                            const isSwapping = renderState.highlights.sortSwapping?.includes(idx);
                            let rowClass = "hover:bg-cyber-cardLight/50 transition";
                            
                            if (isSwapping) {
                              rowClass = "bg-cyber-amber/20 text-cyber-amber font-bold border-y border-cyber-amber/35";
                            } else if (isComparing) {
                              rowClass = "bg-cyber-cyan/20 text-cyber-cyan font-bold border-y border-cyber-cyan/35";
                            }

                            return (
                              <tr key={`log-${idx}`} className={rowClass}>
                                <td className="p-3 text-cyber-textMuted text-[10px]">#{idx}</td>
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
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

            </div>
          </div>
          {/* END TABBED VISUALIZATION */}

        </div>
        {/* ═══ END RIGHT VISUALIZATION PANEL ═══ */}

      </div>
      {/* END MAIN WORKSPACE */}

    </div>
  );
}
