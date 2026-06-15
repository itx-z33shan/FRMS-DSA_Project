import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { 
  Shield, 
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
import { MaxHeap, Firewall, Packet, Rule, LogEntry, MAX_PACKETS, HASH_TABLE_SIZE, BSTNode } from './utils/structures';
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
  // BST Tree Visualization layout - Redesigned for Premium Professional Theme
  const renderBSTNode = (node: BSTNode | null, x: number, y: number, dx: number): React.ReactNode[] => {
    if (!node) return [];
    const elements: React.ReactNode[] = [];
    
    const isPath = renderState.highlights.bstPath?.includes(node.ip);
    const isActiveNode = renderState.highlights.bstActiveNode === node.ip;
    
    let circleFill = "#1e293b"; // Slate-800
    let strokeColor = "#334155"; // Slate-700
    let circleClass = "transition-all duration-300 hover:fill-slate-800 hover:stroke-indigo-400";
    
    if (isActiveNode) {
      circleFill = "#ea580c"; // Orange-600
      strokeColor = "#f97316"; // Orange-500
      circleClass = "animate-pulse filter drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]";
    } else if (isPath) {
      circleFill = "#1e1b4b"; // Indigo-950
      strokeColor = "#6366f1"; // Indigo-500
    }

    if (node.left) {
      elements.push(
        <line 
          key={`line-l-${node.ip}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke={isPath && renderState.highlights.bstPath?.includes(node.left.ip) ? "#6366f1" : "#1e293b"} 
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
          stroke={isPath && renderState.highlights.bstPath?.includes(node.right.ip) ? "#6366f1" : "#1e293b"} 
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
          x={x} y={y + 3} 
          textAnchor="middle" fill="#f8fafc" fontSize="8" fontWeight="600"
          className="pointer-events-none font-mono"
        >
          {node.ip.split('.').slice(-2).join('.')}
        </text>
        <title>{`Blocked IP: ${node.ip}`}</title>
      </g>
    );
    
    return elements;
  };

  // Max-Heap Binary Tree Layout - Redesigned for Premium Professional Theme
  const renderHeapNode = (idx: number, x: number, y: number, dx: number): React.ReactNode[] => {
    const activeHeapRules = renderState.heapRules;
    if (idx >= activeHeapRules.length) return [];
    const elements: React.ReactNode[] = [];
    const leftIdx = 2 * idx + 1;
    const rightIdx = 2 * idx + 2;
    const rule = activeHeapRules[idx];
    
    const isComparing = renderState.highlights.heapComparing?.includes(idx);
    const isSwapping = renderState.highlights.heapSwapping?.includes(idx);
    
    let circleFill = "#0f172a"; // slate-900
    let strokeColor = rule.action === "BLOCK" ? "#f43f5e" : "#10b981"; // state-block : state-allow
    let circleClass = "transition-all duration-300 hover:fill-slate-800";
    
    if (isSwapping) {
      circleFill = "#ea580c"; // orange-600
      strokeColor = "#ea580c";
      circleClass = "animate-bounce filter drop-shadow-[0_0_8px_rgba(234,88,12,0.6)]";
    } else if (isComparing) {
      circleFill = "#1e1b4b"; // Indigo-950
      strokeColor = "#6366f1"; // Indigo-500
    }
    
    if (leftIdx < activeHeapRules.length) {
      elements.push(
        <line 
          key={`h-line-l-${idx}`}
          x1={x} y1={y} x2={x - dx} y2={y + 50} 
          stroke={isComparing && renderState.highlights.heapComparing?.includes(leftIdx) ? "#6366f1" : "#1e293b"} 
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
          stroke={isComparing && renderState.highlights.heapComparing?.includes(rightIdx) ? "#6366f1" : "#1e293b"} 
          strokeWidth="2"
        />
      );
      elements.push(...renderHeapNode(rightIdx, x + dx, y + 50, dx * 0.5));
    }
    
    elements.push(
      <g key={`h-node-${idx}`} className="group cursor-pointer">
        <circle 
          cx={x} cy={y} r="18" 
          fill={circleFill} 
          stroke={strokeColor} 
          strokeWidth="2" 
          className={circleClass}
        />
        <text 
          x={x} y={y - 1} 
          textAnchor="middle" fill="#f8fafc" fontSize="8.5" fontWeight="700"
          className="pointer-events-none font-sans"
        >
          {rule.ruleID}
        </text>
        <text 
          x={x} y={y + 8} 
          textAnchor="middle" fill="#94a3b8" fontSize="7" fontWeight="500"
          className="pointer-events-none font-mono"
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
    <div className="h-screen w-screen bg-[#090d16] text-[#f8fafc] flex flex-col overflow-hidden font-sans antialiased relative">
      
      {/* Premium mesh background glows */}
      <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(ellipse 60% 40% at 20% 0%, rgba(99,102,241,0.06) 0%, transparent 60%), radial-gradient(ellipse 50% 50% at 80% 100%, rgba(139,92,246,0.05) 0%, transparent 60%)' }}></div>
      <div className="absolute top-0 left-1/3 w-[700px] h-[400px] bg-indigo-600/[0.03] rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-violet-600/[0.04] rounded-full blur-[150px] pointer-events-none"></div>

      {/* TOP NAVIGATION HEADER */}
      <header className="flex-shrink-0 bg-[#0b101f]/90 backdrop-blur-xl border-b border-slate-800/70 px-6 py-3.5 flex items-center justify-between z-30">
        <div className="flex items-center gap-3.5">
          {/* Brand Shield */}
          <div className="relative p-2.5 rounded-xl border border-indigo-500/25" style={{ background: 'linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(139,92,246,0.10) 100%)' }}>
            <Shield className="w-5 h-5 text-indigo-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-emerald-400 rounded-full border border-[#0b101f]" style={{ animation: 'scanPulse 2s infinite ease-in-out' }}></span>
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-[15px] font-bold font-display tracking-tight text-white">
                FRMS
              </h1>
              <span className="text-[10px] text-slate-500 font-medium">·</span>
              <span className="text-[13px] font-semibold text-slate-300 font-display">Firewall Control Deck</span>
              <span className="text-[9px] px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 font-bold tracking-wider uppercase">Live</span>
            </div>
            <p className="text-[10px] text-slate-500 font-medium mt-0.5 tracking-wide">
              Rule Management System · DSA Traversal Stepper
            </p>
          </div>
        </div>

        {/* HEADER STATS INDICATORS */}
        <div className="hidden md:flex items-center gap-3">
          {/* Stat Pills */}
          <div className="flex items-center gap-1 bg-slate-900/60 border border-slate-800/80 rounded-xl px-3 py-2">
            {[
              { label: 'Processed', val: stats.total,   color: 'text-indigo-400' },
              { label: 'Blocked',   val: stats.blocked,  color: 'text-rose-400' },
              { label: 'Allowed',   val: stats.allowed,  color: 'text-emerald-400' },
              { label: 'Block Rate',val: `${blockRate}%`, color: 'text-amber-500' },
            ].map((stat, i, arr) => (
              <React.Fragment key={stat.label}>
                <div className="px-3 text-center">
                  <div className="text-[8px] text-slate-500 font-semibold uppercase tracking-wider">{stat.label}</div>
                  <div className={`text-sm font-bold font-mono mt-0.5 ${stat.color}`}>{stat.val}</div>
                </div>
                {i < arr.length - 1 && <span className="text-slate-800 text-lg font-thin">|</span>}
              </React.Fragment>
            ))}
          </div>

          <div className="hidden lg:flex items-center gap-2.5 text-[10px] text-slate-500 font-mono bg-slate-900/50 px-3.5 py-2 rounded-xl border border-slate-800/60">
            <span className="text-slate-600">CSC211</span>
            <span className="text-slate-800">·</span>
            <span className="text-slate-400">Attaullah · Monis · Zeeshan</span>
          </div>

          <button 
            onClick={() => setSidebarCollapsed(s => !s)} 
            title={sidebarCollapsed ? "Expand Config Panel" : "Collapse Config Panel"} 
            aria-label="Toggle config panel" 
            className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-500 hover:text-indigo-400 hover:border-indigo-500/40 hover:bg-indigo-600/5 transition-all duration-200"
          >
            <ArrowRightLeft className={`w-4 h-4 transition-transform duration-300 ${sidebarCollapsed ? 'rotate-180' : ''}`} />
          </button>
        </div>
      </header>

      {/* DASHBOARD GRID: SIDEBAR + MAIN WORKSPACE */}
      <div className="flex-1 flex min-h-0 overflow-hidden relative z-20">

        {/* ═══════════ CONFIGURATION SIDEBAR (LEFT) ═══════════ */}
        <aside className={`${sidebarCollapsed ? 'w-16' : 'w-80'} h-full flex-shrink-0 flex flex-col overflow-hidden border-r border-slate-800 bg-[#0b101f]/70 transition-all duration-300`}> 

          {/* Compact view when sidebar collapsed */}
          {sidebarCollapsed && (
            <div className="flex flex-col items-center py-6 gap-4">
              <button 
                onClick={() => setSidebarCollapsed(false)} 
                title="Expand Sidebar" 
                aria-label="Expand sidebar" 
                className="p-2.5 rounded-xl bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 hover:bg-indigo-600/20 transition"
              >
                <ArrowRightLeft className="w-4 h-4 text-indigo-400" />
              </button>
              <div className="flex flex-col gap-3 mt-6">
                <button onClick={handleLoadDefaults} title="Load Default Configs" className="p-3 rounded-xl hover:bg-slate-800 transition text-slate-400 hover:text-white"><RefreshCw className="w-5 h-5" /></button>
                <button onClick={handleStepProcess} title="Step Single Packet" className="p-3 rounded-xl hover:bg-slate-800 transition text-slate-400 hover:text-white"><Play className="w-5 h-5" /></button>
                <button onClick={handleAnimateProcessPacket} title="Step with Animations" className="p-3 rounded-xl hover:bg-slate-800 transition text-slate-400 hover:text-white"><Activity className="w-5 h-5" /></button>
                <button onClick={handleProcessAll} title="Process All in Queue" className="p-3 rounded-xl hover:bg-slate-800 transition text-slate-400 hover:text-white"><PlayCircle className="w-5 h-5" /></button>
                <button onClick={handleReset} title="Reset Inspection Queue" className="p-3 rounded-xl hover:bg-slate-800 transition text-slate-400 hover:text-white"><Trash2 className="w-5 h-5" /></button>
              </div>
            </div>
          )}

          {/* Expanded Configuration Panel */}
          <div className={`${sidebarCollapsed ? 'hidden' : 'flex flex-col h-full min-h-0'} w-full`}> 

            {/* MINI LIVE TRAFFIC MAP (PINNED TOP) */}
            <div className="px-4 pt-3 pb-3 border-b border-slate-800/60 bg-[#0b101f] relative overflow-hidden flex-shrink-0">
              <div className="flex items-center gap-1.5 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Live Traffic Monitor</span>
              </div>
              <div className="relative z-10">
                <TrafficNetworkCanvas lastTriggerPkt={lastTriggerPkt} compact />
              </div>
            </div>

            {/* SCROLLABLE SIDEBAR SECTION */}
            <div className="flex-1 overflow-y-auto p-4 space-y-5 scrollbar-thin">

              {/* QUICK PLAYER CONTROLLER CARD */}
              <div className="rounded-xl overflow-hidden border border-indigo-500/15" style={{ background: 'linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(15,23,42,0.95) 100%)' }}>
                <div className="px-4 py-3 flex items-center justify-between border-b border-indigo-500/10">
                  <div className="flex items-center gap-2">
                    <div className="w-1.5 h-5 rounded-full bg-indigo-500/60"></div>
                    <span className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest">Engine Control</span>
                  </div>
                  <span className="flex items-center gap-1.5 font-mono text-[9px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> ONLINE
                  </span>
                </div>
                <div className="p-3 grid grid-cols-2 gap-2">
                  <button onClick={handleLoadDefaults} title="Load standard rules and packages" className="py-2 px-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:border-slate-700 hover:text-white transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer">
                    <RefreshCw className="w-3.5 h-3.5" /> Defaults
                  </button>
                  <button onClick={handleStepProcess} title="Inspect next packet in circular queue" className="py-2 px-3 rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-xs font-semibold text-indigo-400 hover:bg-indigo-500/20 hover:border-indigo-500/40 transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer">
                    <Play className="w-3.5 h-3.5" /> Step Pkt
                  </button>
                  <button onClick={handleAnimateProcessPacket} title="Play visual stepper trace of algorithms" className="py-2 px-3 rounded-lg bg-violet-500/10 border border-violet-500/25 text-xs font-semibold text-violet-400 hover:bg-violet-500/20 hover:border-violet-500/40 transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer">
                    <Activity className="w-3.5 h-3.5" /> Animate
                  </button>
                  <button onClick={handleProcessAll} title="Inspect entire queue instantly" className="py-2 px-3 rounded-lg text-xs font-bold text-white transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer hover:brightness-110" style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', boxShadow: '0 2px 12px rgba(99,102,241,0.25)' }}>
                    <PlayCircle className="w-3.5 h-3.5" /> Process All
                  </button>
                  <button onClick={handleReset} title="Clear queue, blocks, and rules" className="col-span-2 py-2 rounded-lg bg-rose-500/8 border border-rose-500/20 text-xs font-semibold text-rose-400 hover:bg-rose-500/15 hover:border-rose-500/35 transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer">
                    <Trash2 className="w-3.5 h-3.5" /> Reset Firewall
                  </button>
                </div>
              </div>

              {/* DYNAMIC PIPELINE VERDICT FEEDBACK CARD */}
              {stepResult && (
                <div className={`rounded-xl border overflow-hidden animate-fade-in relative ${stepResult.action === "BLOCKED" ? 'border-rose-500/30 bg-rose-500/[0.04]' : 'border-emerald-500/30 bg-emerald-500/[0.04]'}`}>
                  {/* Top gradient accent bar */}
                  <div className={`h-0.5 w-full ${stepResult.action === "BLOCKED" ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ boxShadow: stepResult.action === 'BLOCKED' ? '0 0 12px rgba(244,63,94,0.5)' : '0 0 12px rgba(16,185,129,0.5)' }}></div>
                  <div className="p-3.5">
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${stepResult.action === "BLOCKED" ? 'bg-rose-400' : 'bg-emerald-400'} animate-pulse`}></span>
                        <span className={`text-[10px] font-bold tracking-widest uppercase ${stepResult.action === "BLOCKED" ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {stepResult.action}
                        </span>
                      </div>
                      <button onClick={() => setStepResult(null)} className="text-slate-600 hover:text-slate-300 transition">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                    <div className="space-y-1.5 font-mono text-[11px]">
                      {[
                        { label: 'Source', val: stepResult.packet.sourceIP },
                        { label: 'Dest', val: stepResult.packet.destIP },
                        { label: 'Port (Proto)', val: `${stepResult.packet.port} (${stepResult.packet.protocol})` },
                        { label: 'Matched Rule', val: stepResult.ruleID, highlight: true },
                        { label: 'Priority', val: String(stepResult.priority) },
                      ].map(row => (
                        <div key={row.label} className="flex justify-between items-center">
                          <span className="text-slate-500">{row.label}</span>
                          <span className={`font-semibold ${row.highlight ? 'text-indigo-400' : 'text-slate-200'}`}>{row.val}</span>
                        </div>
                      ))}
                    </div>
                    <div className="text-[9px] text-slate-600 border-t border-slate-800/60 mt-2.5 pt-2 text-center">
                      Resolved via {stepResult.checkStep}
                    </div>
                  </div>
                </div>
              )}

              {/* DOCKET CARD 1: ADD RULE FORM */}
              <div className="bg-slate-900/30 border border-slate-800/60 rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-slate-800/60 flex items-center gap-2" style={{ background: 'linear-gradient(90deg, rgba(99,102,241,0.06) 0%, transparent 100%)' }}>
                  <div className="w-1 h-4 rounded-full bg-indigo-500"></div>
                  <h3 className="text-[10px] font-bold uppercase tracking-widest text-indigo-400">Register Firewall Rule</h3>
                </div>
                <div className="p-4">
                <form onSubmit={handleAnimateAddRule} className="space-y-3 font-mono text-[11px]">
                  <div className="grid grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Rule ID</label>
                      <input 
                        type="text" 
                        value={newRule.ruleID}
                        onChange={e => setNewRule(prev => ({ ...prev, ruleID: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 transition"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Target IP</label>
                      <input 
                        type="text" 
                        value={newRule.targetIP}
                        onChange={e => setNewRule(prev => ({ ...prev, targetIP: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 transition"
                        placeholder="192.168.1.100"
                      />
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Action</label>
                      <select 
                        value={newRule.action} 
                        onChange={e => setNewRule(prev => ({ ...prev, action: e.target.value as 'BLOCK' | 'ALLOW' }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500 transition cursor-pointer"
                      >
                        <option value="BLOCK">BLOCK</option>
                        <option value="ALLOW">ALLOW</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Priority</label>
                      <input 
                        type="number" 
                        min="1" 
                        max="10" 
                        value={newRule.priority}
                        onChange={e => setNewRule(prev => ({ ...prev, priority: Number(e.target.value) }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500 transition"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Protocol</label>
                      <select 
                        value={newRule.protocol} 
                        onChange={e => setNewRule(prev => ({ ...prev, protocol: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500 transition cursor-pointer"
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
                    title="Insert rule into Hash Table & Heap Queue"
                    className="w-full mt-2 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-sans font-semibold transition flex items-center justify-center gap-1.5 shadow-lg shadow-indigo-500/10 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" /> Insert to Table & Heap
                  </button>
                </form>
                </div>
              </div>

              {/* DOCKET CARD 2: MANUALLY PUSH PACKETS */}
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2" style={{ background: 'linear-gradient(90deg, rgba(16,185,129,0.06) 0%, transparent 100%)' }}>
                  <div className="w-1 h-4 rounded-full bg-emerald-500"></div>
                  <h3 className="text-[10px] font-bold uppercase tracking-widest text-emerald-400">Inject Manual Packet</h3>
                </div>
                <div className="p-4">
                <form onSubmit={handleAddPacket} className="space-y-3 font-mono text-[11px]">
                  <div className="grid grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Source IP</label>
                      <input 
                        type="text" 
                        value={newPacket.sourceIP}
                        onChange={e => setNewPacket(prev => ({ ...prev, sourceIP: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20 transition"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Dest IP</label>
                      <input 
                        type="text" 
                        value={newPacket.destIP}
                        onChange={e => setNewPacket(prev => ({ ...prev, destIP: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20 transition"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Port</label>
                      <input 
                        type="number" 
                        value={newPacket.port}
                        onChange={e => setNewPacket(prev => ({ ...prev, port: Number(e.target.value) }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 transition"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Protocol</label>
                      <select 
                        value={newPacket.protocol} 
                        onChange={e => setNewPacket(prev => ({ ...prev, protocol: e.target.value }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 transition cursor-pointer"
                      >
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="HTTP">HTTP</option>
                        <option value="ANY">ANY</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Size (B)</label>
                      <input 
                        type="number" 
                        value={newPacket.size}
                        onChange={e => setNewPacket(prev => ({ ...prev, size: Number(e.target.value) }))}
                        className="w-full bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 transition"
                      />
                    </div>
                  </div>

                  <button 
                    type="submit" 
                    title="Insert packet to FIFO queue buffer"
                    className="w-full mt-2 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-sans font-semibold transition flex items-center justify-center gap-1.5 shadow-lg shadow-emerald-500/10 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" /> Push to Circular Queue
                  </button>
                  </form>
                </div>
              </div>

              {/* DOCKET CARD 3: LOGS BINARY SEARCH */}
              <div className="bg-slate-900/30 border border-slate-800/60 rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-slate-800/60 flex items-center gap-2" style={{ background: 'linear-gradient(90deg, rgba(245,158,11,0.06) 0%, transparent 100%)' }}>
                  <div className="w-1 h-4 rounded-full bg-amber-500"></div>
                  <h3 className="text-[10px] font-bold uppercase tracking-widest text-amber-400">Binary Search Logs</h3>
                </div>
                <div className="p-4">
                <form onSubmit={handleSearchLogs} className="space-y-3 font-mono text-[11px]">
                  <div>
                    <label className="block text-[9px] text-slate-400 uppercase font-sans mb-1 font-semibold">Source IP (Exact)</label>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        value={searchIP}
                        onChange={e => setSearchIP(e.target.value)}
                        placeholder="e.g. 192.168.1.10"
                        className="flex-1 bg-slate-950/60 border border-slate-800 p-2 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500/20 transition"
                      />
                      <button 
                        type="submit" 
                        title="Execute binary search on logs"
                        className="px-3 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 font-sans font-bold rounded-lg transition flex items-center gap-1 shadow cursor-pointer"
                      >
                        <Search className="w-3.5 h-3.5" /> Search
                      </button>
                    </div>
                  </div>
                </form>

                {/* Search outcomes rendered inside sidebar */}
                {hasSearched && (
                  <div className="mt-3.5 border-t border-slate-800 pt-3.5 space-y-2.5 max-h-[200px] overflow-y-auto pr-1">
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wide flex justify-between">
                      <span>Matches ({searchResults.length}):</span>
                      <button onClick={() => { setHasSearched(false); setSearchIP(''); }} className="text-rose-400 hover:text-rose-300 font-sans font-semibold">Clear</button>
                    </h4>
                    {searchResults.length === 0 ? (
                      <p className="text-xs text-slate-400 italic">No logs matched this query.</p>
                    ) : (
                      searchResults.map((log, idx) => (
                        <div key={`search-${idx}`} className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg font-mono text-[10px] flex justify-between items-center shadow-sm">
                          <div>
                            <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                              <span className={log.action === "BLOCKED" ? "text-rose-500" : "text-emerald-500"}>●</span>
                              <span>{log.sourceIP}</span>
                            </div>
                            <div className="text-[8.5px] text-slate-400 mt-1">Port {log.port} ({log.protocol}) • {log.timestamp.split(' ')[1]}</div>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-bold text-[9px]">{log.ruleID}</span>
                        </div>
                      ))
                    )}
                  </div>
                )}
                </div>
              </div>

            </div>
          </div>
        </aside>

        {/* ═══════════ MAIN VISUALIZATION STAGE (RIGHT) ═══════════ */}
        <div className="flex-1 flex flex-col overflow-hidden bg-[#090d16] relative">

          {/* DYNAMIC BACKING ALGORITHM STEPPER PANEL */}
          {isStepperActive && stepperSteps.length > 0 && createPortal(
            <div className="fixed top-16 left-1/2 transform -translate-x-1/2 w-[92%] max-w-5xl z-[999] animate-fade-in flex flex-col font-sans text-xs" style={{ background: 'rgba(9,13,22,0.96)', backdropFilter: 'blur(24px)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '16px', boxShadow: '0 20px 60px -10px rgba(0,0,0,0.8), 0 0 0 1px rgba(99,102,241,0.1), 0 0 40px rgba(99,102,241,0.08)', padding: '0' }}>
              {/* Progress bar - gradient */}
              <div className="relative h-0.5 w-full rounded-t-[16px] overflow-hidden bg-slate-800/60">
                <div 
                  className="absolute top-0 left-0 h-full transition-all duration-500 ease-out" 
                  style={{ width: `${((stepperIndex + 1) / stepperSteps.length) * 100}%`, background: 'linear-gradient(90deg, #6366f1, #8b5cf6, #06b6d4)' }}
                ></div>
              </div>
              <div className="px-5 py-4 flex flex-col gap-3">
              
              <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-3">
                <div className="flex-1 space-y-1">
                  <div className="flex items-center gap-2 text-[10px] text-indigo-400 font-bold uppercase tracking-wider">
                    <span>Algorithm Debug Stage ({stepperSteps[stepperIndex].tab.toUpperCase()})</span>
                    <span className="text-slate-800">•</span>
                    <span>Step {stepperIndex + 1} / {stepperSteps.length}</span>
                  </div>
                  <p className="text-white text-sm font-semibold leading-relaxed tracking-tight">
                    {simpleMode ? stepperSteps[stepperIndex].simpleExplanation : stepperSteps[stepperIndex].message}
                  </p>
                </div>

                <div className="flex items-center gap-2.5 bg-slate-900/60 border border-slate-800/80 px-3 py-1.5 rounded-xl flex-shrink-0">
                  <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Analogy View</span>
                  <button
                    onClick={() => setSimpleMode(!simpleMode)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${simpleMode ? 'bg-indigo-600' : 'bg-slate-700'}`}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${simpleMode ? 'translate-x-4.5' : 'translate-x-1'}`} />
                  </button>
                </div>
              </div>

              {/* Segmented Pipeline Stages */}
              <div className="grid grid-cols-4 text-center font-mono text-[9px] gap-2 pt-1">
                {[
                  { label: '1. Conveyor Queue', tab: 'queue', desc: 'FIFO Buffer' },
                  { label: '2. Hash Directory', tab: 'hash', desc: 'Bucket Index' },
                  { label: '3. Blacklist BST', tab: 'bst', desc: 'Range Search' },
                  { label: '4. Logging Registry', tab: 'logs', desc: 'Commit Record' }
                ].map((stage) => {
                  const stepTab = stepperSteps[stepperIndex].tab;
                  const isCurrent = stepTab === stage.tab;
                  let isActive = false;
                  if (stage.tab === 'queue' && (stepTab === 'queue' || stepTab === 'hash' || stepTab === 'bst' || stepTab === 'logs')) isActive = true;
                  if (stage.tab === 'hash' && (stepTab === 'hash' || stepTab === 'bst' || stepTab === 'logs' || stepTab === 'heap')) isActive = true;
                  if (stage.tab === 'bst' && (stepTab === 'bst' || stepTab === 'logs')) isActive = true;
                  if (stage.tab === 'logs' && stepTab === 'logs') isActive = true;
                  return (
                    <div 
                      key={stage.label}
                      className={`p-2 rounded-lg border transition-all duration-300 ${isCurrent ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 font-bold shadow-indigo-glow' : isActive ? 'bg-slate-900 border-slate-800 text-slate-300' : 'border-transparent text-slate-600'}`}
                    >
                      <div className="uppercase tracking-wider font-semibold text-[8px]">{stage.label}</div>
                      <div className="text-[7.5px] opacity-70 mt-0.5">{stage.desc}</div>
                    </div>
                  );
                })}
              </div>

              {/* Player Timeline controls */}
              <div className="flex flex-row justify-between items-center border-t border-slate-800/80 pt-2.5 mt-1 gap-4">
                <div className="flex items-center gap-1.5">
                  <button onClick={() => { setStepperIndex(0); setIsStepperPlaying(false); }} disabled={stepperIndex === 0} className="px-3 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[10px] font-semibold disabled:opacity-40 transition cursor-pointer">Reset</button>
                  <button onClick={() => { setStepperIndex(prev => Math.max(0, prev - 1)); setIsStepperPlaying(false); }} disabled={stepperIndex === 0} className="px-3 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[10px] font-semibold disabled:opacity-40 transition cursor-pointer">◀ Prev</button>
                  <button onClick={() => setIsStepperPlaying(!isStepperPlaying)} className={`px-4.5 py-1 rounded font-bold text-[10px] transition cursor-pointer ${isStepperPlaying ? 'bg-rose-600/20 text-rose-300 border border-rose-500/30' : 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30'}`}>{isStepperPlaying ? '⏸ Pause' : '▶ Play'}</button>
                  <button onClick={() => { setStepperIndex(prev => Math.min(stepperSteps.length - 1, prev + 1)); setIsStepperPlaying(false); }} disabled={stepperIndex === stepperSteps.length - 1} className="px-3 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[10px] font-semibold disabled:opacity-40 transition cursor-pointer">Next ▶</button>
                  <button onClick={() => { setIsStepperActive(false); setIsStepperPlaying(false); syncState(); }} className="ml-2 px-3 py-1 rounded bg-rose-600/10 hover:bg-rose-600/25 border border-rose-500/30 text-rose-400 text-[10px] font-semibold transition cursor-pointer">✕ Exit Trace</button>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] text-slate-400 font-mono font-bold uppercase">{stepperSpeed}ms</span>
                  <input type="range" min="200" max="2000" step="100" value={stepperSpeed} onChange={e => setStepperSpeed(Number(e.target.value))} className="w-24 h-1 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500" />
                </div>
              </div>
              </div>
            </div>, document.body
          )}

          {/* TABBED VISUALIZATIONWORKSPACE */}
          <div className="flex-1 flex flex-col overflow-hidden">  
            
            {/* LARGE TABS NAVIGATION */}
            <div className="flex border-b border-slate-800/80 bg-[#090d16] px-5 pt-2 gap-0.5">
              {[
                { tabName: 'queue', label: 'Queue Buffer',   icon: <Activity className="w-3.5 h-3.5" />, activeColor: 'text-emerald-400', activeBg: 'bg-emerald-500/8', activeBorder: 'border-emerald-500', indicatorColor: 'bg-emerald-500' },
                { tabName: 'hash',  label: 'Hash Directory', icon: <Database className="w-3.5 h-3.5" />, activeColor: 'text-indigo-400',  activeBg: 'bg-indigo-500/8',  activeBorder: 'border-indigo-500',  indicatorColor: 'bg-indigo-500' },
                { tabName: 'heap',  label: 'Priority Heap',  icon: <Flame className="w-3.5 h-3.5" />,    activeColor: 'text-rose-400',    activeBg: 'bg-rose-500/8',    activeBorder: 'border-rose-500',    indicatorColor: 'bg-rose-500' },
                { tabName: 'bst',   label: 'Blacklist BST',  icon: <Network className="w-3.5 h-3.5" />,  activeColor: 'text-cyan-400',    activeBg: 'bg-cyan-500/8',    activeBorder: 'border-cyan-500',    indicatorColor: 'bg-cyan-500' },
                { tabName: 'logs',  label: 'Logs Registry',  icon: <Clock className="w-3.5 h-3.5" />,    activeColor: 'text-amber-400',   activeBg: 'bg-amber-500/8',   activeBorder: 'border-amber-500',   indicatorColor: 'bg-amber-500' }
              ].map(t => {
                const isSelected = activeTab === t.tabName;
                return (
                  <button 
                    key={t.tabName}
                    onClick={() => setActiveTab(t.tabName as any)}
                    className={`relative flex items-center gap-2 px-4 py-3 font-medium text-xs transition-all duration-200 cursor-pointer rounded-t-lg ${
                      isSelected 
                        ? `${t.activeColor} ${t.activeBg} font-semibold` 
                        : 'text-slate-500 hover:text-slate-300 hover:bg-slate-900/30'
                    }`}
                  >
                    {t.icon}
                    <span>{t.label}</span>
                    {/* Active bottom indicator */}
                    {isSelected && (
                      <span className={`absolute bottom-0 left-2 right-2 h-0.5 rounded-t-full ${t.indicatorColor}`}></span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* TAB CONTENT AREAS */}
            <div className={`p-6 flex-1 overflow-y-auto min-h-0 relative ${isStepperActive ? 'pt-36' : ''}`}>
              
              {/* TAB 1: CONVEYOR PACKET QUEUE */}
              {activeTab === 'queue' && (
                <div className="space-y-6 animate-fade-in flex flex-col h-full">
                  <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <h3 className="text-md font-bold font-display text-white">Packet Processing queue (Circular FIFO Array)</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">
                        Live packets enter the circular buffer at the rear index and exit from the front index. Active inspect target: index <span className="text-emerald-400 font-bold font-mono">#{fw.packetQueue.getFrontIdx()}</span>.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="max-w-md bg-emerald-500/5 border border-emerald-500/15 p-3 rounded-xl flex items-start gap-2.5 text-[11px] leading-relaxed">
                        <div className="px-2 py-0.5 bg-emerald-500/10 rounded-md text-emerald-400 font-semibold flex-shrink-0">Analogy</div>
                        <p className="text-slate-300">
                          <strong>Conveyor Belt (FIFO):</strong> A circular queue behaves like luggage claim. Suitcases (packets) are processed one-by-one in the exact order they were loaded (First-In, First-Out).
                        </p>
                      </div>
                    )}
                  </div>
                  
                  {renderState.packets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-2xl p-10 text-slate-500 font-mono text-xs italic">
                      <AlertTriangle className="w-8 h-8 text-amber-500/50 mb-2" />
                      Circular buffer is currently empty! Inject packets using the sidebar.
                    </div>
                  ) : (
                    <div className="space-y-6 flex-grow flex flex-col justify-center">
                      
                      {/* FIFO CONVEYOR VIEW */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5.5 flex items-center justify-start gap-3 overflow-x-auto select-none py-8 scrollbar-thin">
                        {renderState.packets.map((pkt, idx) => {
                          const isActive = renderState.highlights.activeQueueIdx !== undefined && idx === 0;
                          return (
                            <React.Fragment key={`conveyor-${idx}`}>
                              {idx > 0 && <span className="text-slate-800 font-bold shrink-0">➔</span>}
                              <div className={`flex-shrink-0 w-40 bg-slate-900 border p-4.5 rounded-xl font-mono text-[11px] space-y-2 relative transition-all duration-300 shadow-lg ${isActive ? 'border-indigo-500 bg-indigo-500/5 scale-105 shadow-indigo-glow' : idx === 0 ? 'border-emerald-500 bg-emerald-500/5 shadow-emerald-glow' : 'border-slate-800'}`}>
                                {idx === 0 && (
                                  <span className={`absolute -top-2.5 right-3 px-2 py-0.5 rounded-full text-[8px] font-bold uppercase tracking-wider border ${isActive ? 'bg-indigo-600 text-white border-indigo-400' : 'bg-emerald-600 text-white border-emerald-400'}`}>{isActive ? 'INSPECTING' : 'NEXT'}</span>
                                )}
                                <div className="font-bold text-white truncate">{pkt.sourceIP}</div>
                                <div className="text-slate-400 truncate">→ {pkt.destIP}</div>
                                <div className="text-indigo-400">Port: {pkt.port}</div>
                                <div className="text-slate-400 flex justify-between">
                                  <span>{pkt.protocol}</span>
                                  <span className="text-[10px] text-slate-500">{pkt.size} B</span>
                                </div>
                              </div>
                            </React.Fragment>
                          );
                        })}
                      </div>

                      {/* RAW CIRCULAR ARRAY DIAGRAM */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 space-y-4">
                        <div className="flex justify-between items-center">
                          <span className="text-xs font-bold text-slate-300">Circular Memory Buffer Array (Capacity: {MAX_PACKETS})</span>
                          <div className="flex gap-4 font-mono text-[10px] font-semibold">
                            <span className="flex items-center gap-1.5"><span className="w-3 h-3 bg-emerald-500/10 border border-emerald-500/30 rounded-md"></span> Front ({fw.packetQueue.getFrontIdx()})</span>
                            <span className="flex items-center gap-1.5"><span className="w-3 h-3 bg-blue-500/10 border border-blue-500/30 rounded-md"></span> Rear ({fw.packetQueue.getRearIdx()})</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-6 sm:grid-cols-12 gap-2 font-mono text-center">
                          {Array.from({ length: MAX_PACKETS }).map((_, idx) => {
                            const rawArray = fw.packetQueue.getRawArray();
                            const hasP = rawArray[idx] !== null;
                            const isFront = idx === fw.packetQueue.getFrontIdx();
                            const isRear = idx === fw.packetQueue.getRearIdx();
                            
                            let bgClass = "bg-slate-950/20 border-slate-800/60 text-slate-600";
                            if (hasP) bgClass = "bg-slate-900 border-slate-800 text-slate-200";
                            if (isFront) bgClass = "bg-emerald-500/10 border-emerald-500/40 text-emerald-400 font-bold";
                            if (isRear) bgClass = "bg-indigo-500/10 border-indigo-500/40 text-indigo-400 font-bold";
                            
                            if (renderState.highlights.activeQueueIdx === idx) {
                              bgClass = "bg-indigo-600 border-indigo-400 text-white font-bold animate-pulse";
                            }

                            return (
                              <div 
                                key={`circular-${idx}`}
                                className={`border rounded-xl p-1.5 text-[10px] relative flex flex-col justify-between h-14 transition-all ${bgClass}`}
                              >
                                <span className="text-[8px] text-slate-500">#{idx}</span>
                                <span className="font-bold text-xs">{hasP ? 'PKT' : 'ø'}</span>
                                <div className="absolute -bottom-1.5 left-1/2 transform -translate-x-1/2 flex gap-0.5">
                                  {isFront && <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full"></span>}
                                  {isRear && <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full"></span>}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: HASH TABLE */}
              {activeTab === 'hash' && (
                <div className="space-y-6 animate-fade-in flex flex-col h-full">
                  <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <h3 className="text-md font-bold font-display text-white">Rule lookup Hash Directory (Polynomial Chaining)</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">
                        VIP IP rules are indexed instantly via a rolling character polynomial code index `H(IP) = Σ (c_i * 31^i) % 101`. Collisions resolve through linked buckets.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="max-w-md bg-indigo-500/5 border border-indigo-500/15 p-3 rounded-xl flex items-start gap-2.5 text-[11px] leading-relaxed">
                        <div className="px-2 py-0.5 bg-indigo-500/10 rounded-md text-indigo-400 font-semibold flex-shrink-0">Analogy</div>
                        <p className="text-slate-300">
                          <strong>Filing Cabinet (Direct lookup):</strong> Hashing works like a set of alphabetically labeled folders. Instead of searching all files, we calculate the exact folder index for a rule IP, saving lookup time.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE COMPONENT: POLYNOMIAL BENCHMARK */}
                  <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 font-mono text-xs shadow-md">
                    <div className="space-y-1">
                      <h4 className="font-bold text-indigo-400 uppercase tracking-wider">Polynomial Hash Engine Step Tracker</h4>
                      <p className="text-slate-400 text-[10px] font-sans">Type an IP below to animate calculations of intermediate keys and trace lookup bucket collision chains.</p>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={testHashIP}
                        onChange={e => setTestHashIP(e.target.value)}
                        className="bg-slate-950/60 border border-slate-800 p-2.5 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500 w-44 transition"
                      />
                      <button
                        onClick={() => handleAnimateHashTableSearch(testHashIP)}
                        className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-sans font-semibold rounded-lg shadow-lg shadow-indigo-500/15 transition cursor-pointer"
                      >
                        Animate Hash Lookup
                      </button>
                    </div>
                  </div>
                  
                  {renderState.hashBuckets.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-2xl p-10 text-slate-500 font-mono text-xs italic">
                      No lookup rules loaded in hash table. Load defaults.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1">
                      
                      {/* BUCKET SCROLL CONTAINER */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col max-h-[420px]">
                        <h4 className="text-xs font-bold text-slate-300 mb-3.5">Registered Hash Buckets (Cap: {HASH_TABLE_SIZE})</h4>
                        <div className="flex-grow overflow-y-auto space-y-2.5 pr-2 scrollbar-thin">
                          {renderState.hashBuckets.map((bucket) => {
                            const isBucketActive = renderState.highlights.hashBucketIdx === bucket.index;
                            return (
                              <div 
                                key={`bucket-${bucket.index}`} 
                                className={`bg-slate-900 border rounded-xl p-3 flex items-center justify-between transition-all duration-300 ${isBucketActive ? 'border-indigo-500 bg-indigo-500/10 shadow-indigo-glow scale-[1.01]' : 'border-slate-800'}`}
                              >
                                <div className="flex items-center gap-3">
                                  <span className={`px-2 py-0.5 border text-[10px] rounded-lg font-mono font-bold ${isBucketActive ? 'bg-indigo-600 text-white border-indigo-400 shadow-sm' : 'bg-slate-950 border-slate-800 text-indigo-400'}`}>
                                    Index {bucket.index}
                                  </span>
                                  <span className="text-[10px] text-slate-400 font-medium">
                                    Chains: {bucket.chain.length}
                                  </span>
                                </div>
                                <div className="flex items-center gap-1.5 overflow-x-auto max-w-[240px] scrollbar-none">
                                  {bucket.chain.map((rule, idx) => {
                                    const isKeyChecked = renderState.highlights.hashChainKeys?.includes(rule.targetIP);
                                    const isKeyActive = renderState.highlights.hashActiveKey === rule.targetIP;
                                    
                                    let ruleClass = rule.action === "BLOCK" ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
                                    if (isKeyActive) {
                                      ruleClass = "bg-amber-500 text-slate-950 border border-amber-400 font-bold animate-pulse scale-105 shadow-sm";
                                    } else if (isKeyChecked) {
                                      ruleClass = "bg-indigo-600 text-white border border-indigo-400 shadow-sm";
                                    }

                                    return (
                                      <span 
                                        key={`chain-${bucket.index}-${idx}`}
                                        className={`px-2 py-0.5 rounded font-bold text-[9px] font-mono transition-all ${ruleClass}`}
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
 
                      {/* OVERVIEW ACTIVE DIRECTORY RULES */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col max-h-[420px]">
                        <h4 className="text-xs font-bold text-slate-300 mb-3.5">Total Rules Registered ({renderState.heapRules.length})</h4>
                        <div className="flex-grow overflow-y-auto space-y-2 pr-2 scrollbar-thin">
                          {renderState.heapRules.map((rule) => (
                            <div key={`rule-list-${rule.ruleID}`} className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex justify-between items-center transition hover:bg-slate-800 hover:border-slate-700 shadow-sm">
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-bold text-white text-xs">{rule.ruleID}</span>
                                  <span className={`px-2 py-0.5 text-[9px] font-bold rounded-full border ${rule.action === "BLOCK" ? "bg-rose-500/10 text-rose-400 border-rose-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`}>
                                    {rule.action}
                                  </span>
                                </div>
                                <div className="text-[10px] text-slate-400 font-mono mt-1.5">IP: {rule.targetIP}</div>
                                <div className="text-[9.5px] text-slate-500 mt-1 font-mono">Proto: {rule.protocol} | Priority: {rule.priority} | Hits: {rule.hitCount}</div>
                              </div>
                              <button 
                                onClick={() => handleRemoveRule(rule.targetIP)}
                                className="p-2 rounded-lg hover:bg-rose-600/10 hover:text-rose-400 text-slate-400 transition cursor-pointer"
                                title="Delete rule"
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

              {/* TAB 3: MAX-HEAP RULE PRIORITY QUEUE */}
              {activeTab === 'heap' && (
                <div className="space-y-6 animate-fade-in flex flex-col h-full">
                  <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <h3 className="text-md font-bold font-display text-white">Rule Priority Stack (Binary Max-Heap Array)</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">
                        Rules are sorted automatically by priority inside a binary tree layout mapped onto a linear array. Root node (index 0) represents maximum priority.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="max-w-md bg-rose-500/5 border border-rose-500/15 p-3 rounded-xl flex items-start gap-2.5 text-[11px] leading-relaxed">
                        <div className="px-2 py-0.5 bg-rose-500/10 rounded-md text-rose-400 font-semibold flex-shrink-0">Analogy</div>
                        <p className="text-slate-300">
                          <strong>Emergency Room triage:</strong> The Max-Heap works like a hospital waiting list sorted by severity. The highest priority case is always at the top, and bubble-up/down processes restructure entries when priorities change.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE CONTROLS: PRIORITY EXTRACTION */}
                  <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 font-mono text-xs shadow-md">
                    <div className="space-y-1">
                      <h4 className="font-bold text-rose-400 uppercase tracking-wider">Interactive Heap Restructuring Demo</h4>
                      <p className="text-slate-400 text-[10px] font-sans">Pop the maximum priority element from the heap to trace how nodes swap positions dynamically (Bubble-Down Heapify).</p>
                    </div>
                    <button
                      onClick={handleAnimatePopHeap}
                      disabled={renderState.heapRules.length === 0}
                      className="px-4 py-2.5 bg-rose-600/15 hover:bg-rose-600/25 border border-rose-500/30 text-rose-400 font-sans font-semibold rounded-lg shadow transition-all cursor-pointer disabled:opacity-40"
                    >
                      Animate Pop Root (Priority Dequeue)
                    </button>
                  </div>
                  
                  {renderState.heapRules.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-2xl p-10 text-slate-500 font-mono text-xs italic">
                      Max-Heap is currently empty! Add rules using the config panel.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE SVG GRAPH CONTAINER */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col items-center justify-center min-h-[360px] relative">
                        <span className="absolute top-4 left-4 text-[10px] font-bold text-slate-500 uppercase tracking-wider">Dynamic Binary Heap Tree Graph</span>
                        <svg className="w-full max-w-[480px] h-[280px]" viewBox="0 0 500 280">
                          {renderHeapNode(0, 250, 30, 110)}
                        </svg>
                      </div>

                      {/* FLAT ARRAY DIRECT INDEX REPRESENTATION */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col">
                        <h4 className="text-xs font-bold text-slate-300 mb-3.5">Flat Heap Array Layout representation</h4>
                        <div className="grid grid-cols-4 sm:grid-cols-6 gap-2.5 font-mono text-center">
                          {renderState.heapRules.map((rule, idx) => {
                            const isComparing = renderState.highlights.heapComparing?.includes(idx);
                            const isSwapping = renderState.highlights.heapSwapping?.includes(idx);
                            
                            let borderClass = "border-slate-800 bg-slate-900 text-slate-300";
                            if (isSwapping) {
                              borderClass = "border-orange-500 bg-orange-600/15 text-orange-400 font-bold animate-pulse";
                            } else if (isComparing) {
                              borderClass = "border-indigo-500 bg-indigo-600/15 text-indigo-400 font-bold";
                            }

                            return (
                              <div 
                                key={`heap-flat-${idx}`}
                                className={`border rounded-xl p-2.5 text-xs relative flex flex-col justify-between h-15 shadow-sm transition ${borderClass}`}
                              >
                                <span className="text-[8px] text-slate-500">Idx {idx}</span>
                                <span className="font-bold text-white">{rule.ruleID}</span>
                                <span className="text-[9px] text-slate-400 font-medium">Pri: {rule.priority}</span>
                                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ${rule.action === "BLOCK" ? "bg-rose-500" : "bg-emerald-500"}`}></span>
                              </div>
                            );
                          })}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-4 leading-relaxed bg-slate-950/20 p-3 rounded-lg border border-slate-800/40">
                          <p className="font-semibold text-slate-400 mb-1 font-sans">Structural Properties:</p>
                          <ul className="list-disc pl-4 space-y-1">
                            <li>Parent node of index `i` is located at index `⌊(i-1)/2⌋`</li>
                            <li>Left child is at index `2*i + 1` • Right child is at index `2*i + 2`</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: BST IP BLACKLIST TREE */}
              {activeTab === 'bst' && (
                <div className="space-y-6 animate-fade-in flex flex-col h-full">
                  <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <h3 className="text-md font-bold font-display text-white">Blocked IP Directory (Binary Search Tree)</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">
                        High-traffic IP Ranges are blocked using a Binary Search Tree (BST) sorted lexicographically. Searches run in O(log N) time complexity.
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="max-w-md bg-cyan-500/5 border border-cyan-500/15 p-3 rounded-xl flex items-start gap-2.5 text-[11px] leading-relaxed">
                        <div className="px-2 py-0.5 bg-cyan-500/10 rounded-md text-cyan-400 font-semibold flex-shrink-0">Analogy</div>
                        <p className="text-slate-300">
                          <strong>Branching Directory (Sorted branches):</strong> The BST organizes sorted IP paths. At each junction node, smaller addresses branch left and larger ones branch right, skipping half the search list at each step.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* INTERACTIVE COMPONENT: BST TRAVERSAL SEARCH */}
                  <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 font-mono text-xs shadow-md">
                    <div className="space-y-1">
                      <h4 className="font-bold text-cyan-400 uppercase tracking-wider">Lexicographical BST Search Analyzer</h4>
                      <p className="text-slate-400 text-[10px] font-sans">Type an IP address to watch how a query checks left or right branches step-by-step through the tree structure.</p>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={testBSTIP}
                        onChange={e => setTestBSTIP(e.target.value)}
                        className="bg-slate-950/60 border border-slate-800 p-2.5 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500 w-44 transition"
                      />
                      <button
                        onClick={() => handleAnimateBSTSearch(testBSTIP)}
                        className="px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-sans font-semibold rounded-lg shadow-lg shadow-cyan-500/15 transition cursor-pointer"
                      >
                        Animate Tree Search
                      </button>
                    </div>
                  </div>
                  
                  {bstIPs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-2xl p-10 text-slate-500 font-mono text-xs italic">
                      Blacklist IP Tree is empty! Load configurations.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1">
                      
                      {/* TREE SVG DIAGRAM */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col items-center justify-center min-h-[360px] relative">
                        <span className="absolute top-4 left-4 text-[10px] font-bold text-slate-500 uppercase tracking-wider">Binary Tree Graph Visualization</span>
                        <svg className="w-full max-w-[480px] h-[280px]" viewBox="0 0 500 280">
                          {renderBSTNode(fw.ipTree.getRoot(), 250, 30, 110)}
                        </svg>
                      </div>

                      {/* SORTED BLOCKLIST LOG INORDER LIST */}
                      <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-5 flex flex-col">
                        <h4 className="text-xs font-bold text-slate-300 mb-3.5">Sorted Blocked IPs (BST In-Order Traversal List)</h4>
                        <div className="flex-grow overflow-y-auto space-y-2 pr-2 scrollbar-thin max-h-[260px]">
                          {bstIPs.map((ip, idx) => {
                            const isActive = renderState.highlights.bstActiveNode === ip;
                            const isPath = renderState.highlights.bstPath?.includes(ip);
                            
                            let nodeStyle = "bg-slate-900 border-slate-800 text-slate-300";
                            if (isActive) {
                              nodeStyle = "bg-orange-600/10 border-orange-500 text-orange-400 font-semibold animate-pulse";
                            } else if (isPath) {
                              nodeStyle = "bg-indigo-600/10 border-indigo-500 text-indigo-400 font-semibold";
                            }

                            return (
                              <div key={`bst-list-${idx}`} className={`border rounded-xl p-3 flex justify-between items-center font-mono text-xs shadow-sm transition ${nodeStyle}`}>
                                <span>{ip}</span>
                                <span className="text-[10px] text-slate-500">Node #{idx + 1}</span>
                              </div>
                            );
                          })}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-4 bg-slate-950/20 p-3 rounded-lg border border-slate-800/40">
                          <p className="font-semibold text-slate-400 mb-1 font-sans">Traversal Property:</p>
                          <p>BST In-Order Traversal checks elements recursively (Left Child ➔ Parent ➔ Right Child), returning a perfectly sorted set of IP addresses in ascending order.</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: SORTING BENCHMARKS & LOGS */}
              {activeTab === 'logs' && (
                <div className="space-y-6 animate-fade-in flex flex-col h-full">
                  <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <h3 className="text-md font-bold font-display text-white">Firewall Inspection Logs & Sorting Benchmark</h3>
                      <p className="text-xs text-slate-400 font-medium mt-1">
                        View historical log audits. Benchmark custom C++ ported algorithms: Quick Sort (on timestamps) and Merge Sort (on severity levels).
                      </p>
                    </div>

                    {simpleMode && (
                      <div className="max-w-md bg-amber-500/5 border border-amber-500/15 p-3 rounded-xl flex items-start gap-2.5 text-[11px] leading-relaxed">
                        <div className="px-2 py-0.5 bg-amber-500/10 rounded-md text-amber-500 font-semibold flex-shrink-0">Analogy</div>
                        <p className="text-slate-300">
                          <strong>File Room Organizer:</strong> Sorting processes log registers. Quick Sort uses a pivot point to swap elements, while Merge Sort splits logs in half and combines them in priority order.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* BENCHMARK STATS & BENCHMARK TRIGGERS */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-shrink-0">
                    
                    {/* TRIGGER CONTROLS CARD */}
                    <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-4.5 space-y-3.5 shadow-md">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-sans">Benchmark Algorithm Players</h4>
                      <div className="grid grid-cols-2 gap-3.5">
                        <div className="space-y-2">
                          <span className="text-[10px] text-slate-400 font-semibold">Quick Sort (By Time)</span>
                          <button 
                            onClick={() => handleSortLogs('time')}
                            className="w-full px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-sans font-semibold text-slate-200 hover:bg-slate-800 transition flex items-center justify-center gap-2 cursor-pointer shadow-sm"
                          >
                            <Clock className="w-3.5 h-3.5" /> Instant Sort
                          </button>
                          <button 
                            onClick={() => handleAnimateSort('time')}
                            className="w-full px-3.5 py-2 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 font-sans font-semibold text-[11px] transition flex items-center justify-center gap-2 cursor-pointer"
                          >
                            <Activity className="w-3.5 h-3.5" /> Animate Trace
                          </button>
                        </div>
                        <div className="space-y-2">
                          <span className="text-[10px] text-slate-400 font-semibold">Merge Sort (By Severity)</span>
                          <button 
                            onClick={() => handleSortLogs('severity')}
                            className="w-full px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-sans font-semibold text-slate-200 hover:bg-slate-800 transition flex items-center justify-center gap-2 cursor-pointer shadow-sm"
                          >
                            <ArrowRightLeft className="w-3.5 h-3.5" /> Instant Sort
                          </button>
                          <button 
                            onClick={() => handleAnimateSort('severity')}
                            className="w-full px-3.5 py-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 text-amber-500 font-sans font-semibold text-[11px] transition flex items-center justify-center gap-2 cursor-pointer"
                          >
                            <Activity className="w-3.5 h-3.5" /> Animate Trace
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* BENCHMARK STATS OUTPUT CARD */}
                    <div className="bg-slate-900/30 border border-slate-800 rounded-2xl p-4.5 flex flex-col justify-between shadow-md">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-sans">Metrics Evaluation</h4>
                      <div className="grid grid-cols-3 gap-2.5 font-mono text-xs mt-3">
                        <div className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60 text-center">
                          <div className="text-[9px] text-slate-500">Comparisons</div>
                          <div className="text-sm font-bold text-indigo-400 mt-1">{fw.logManager.sortMetrics.comparisons}</div>
                        </div>
                        <div className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60 text-center">
                          <div className="text-[9px] text-slate-500">Array Writes</div>
                          <div className="text-sm font-bold text-indigo-400 mt-1">{fw.logManager.sortMetrics.swaps}</div>
                        </div>
                        <div className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60 text-center">
                          <div className="text-[9px] text-slate-500">Time Taken</div>
                          <div className="text-sm font-bold text-emerald-400 mt-1 font-mono">{fw.logManager.sortMetrics.timeTakenMs} <span className="text-[9px] text-slate-400">ms</span></div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* INSPECTION AUDIT RECORDS LOGS TABLE */}
                  {renderState.logs.length === 0 ? (
                    <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-2xl p-10 text-slate-500 font-mono text-xs italic">
                      Audit log records are empty. Process packet queue to insert records.
                    </div>
                  ) : (
                    <div className="border border-slate-800 rounded-2xl overflow-hidden flex-1 max-h-[350px] overflow-y-auto shadow-lg bg-slate-900/10 scrollbar-thin">
                      <table className="w-full text-left font-mono text-[11px] border-collapse">
                        <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[9px] font-bold sticky top-0">
                          <tr>
                            <th className="p-3.5">Offset</th>
                            <th className="p-3.5">Timestamp</th>
                            <th className="p-3.5">Verdict</th>
                            <th className="p-3.5">SourceIP</th>
                            <th className="p-3.5">Port (Proto)</th>
                            <th className="p-3.5">Matched ID</th>
                            <th className="p-3.5 text-right font-bold">Priority</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {renderState.logs.map((log, idx) => {
                            const isComparing = renderState.highlights.sortComparing?.includes(idx);
                            const isSwapping = renderState.highlights.sortSwapping?.includes(idx);
                            let rowClass = "hover:bg-slate-900/40 transition";
                            
                            if (isSwapping) {
                              rowClass = "bg-amber-500/10 text-amber-400 font-bold border-y border-amber-500/30";
                            } else if (isComparing) {
                              rowClass = "bg-indigo-500/10 text-indigo-400 font-bold border-y border-indigo-500/30";
                            }

                            return (
                              <tr key={`log-${idx}`} className={rowClass}>
                                <td className="p-3.5 text-slate-500 text-[10px]">#{idx}</td>
                                <td className="p-3.5 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                                <td className="p-3.5 font-bold">
                                  <span className={`px-2 py-0.5 rounded-full text-[9px] border ${log.action === "BLOCKED" ? "bg-rose-500/10 text-rose-400 border-rose-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`}>
                                    {log.action}
                                  </span>
                                </td>
                                <td className="p-3.5 text-slate-200">{log.sourceIP}</td>
                                <td className="p-3.5 text-indigo-400">{log.port} <span className="text-[10px] text-slate-500">({log.protocol})</span></td>
                                <td className="p-3.5 text-slate-400 font-bold">{log.ruleID}</td>
                                <td className="p-3.5 text-right font-bold text-slate-200">{log.priority}</td>
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
