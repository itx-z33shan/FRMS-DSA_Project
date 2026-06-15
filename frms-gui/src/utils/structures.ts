// ============================================================
//   FIREWALL RULE MANAGEMENT SYSTEM (FRMS) - TYPESCRIPT PORT
//   Replicates the C++ custom data structure implementations.
// ============================================================

export const HASH_TABLE_SIZE = 101;
export const MAX_LOGS = 1000;
export const MAX_PACKETS = 24;
export const MAX_RULES = 200;

export interface HeapTraceStep {
    array: Rule[];
    comparing: [number, number] | null;
    swapping: [number, number] | null;
    message: string;
}

export interface SortTraceStep {
    logs: LogEntry[];
    comparing: [number, number] | null;
    swapping: [number, number] | null;
    message: string;
}

// ============================================================
//  CLASS: Packet
// ============================================================
export class Packet {
    public sourceIP: string;
    public destIP: string;
    public port: number;
    public protocol: string;
    public size: number;

    constructor(
        sourceIP: string = "",
        destIP: string = "",
        port: number = 0,
        protocol: string = "",
        size: number = 0
    ) {
        this.sourceIP = sourceIP;
        this.destIP = destIP;
        this.port = port;
        this.protocol = protocol;
        this.size = size;
    }
}

// ============================================================
//  CLASS: Rule
// ============================================================
export class Rule {
    public hitCount: number = 0;
    public ruleID: string;
    public targetIP: string;
    public action: "BLOCK" | "ALLOW";
    public priority: number;
    public protocol: string;

    constructor(
        ruleID: string = "",
        targetIP: string = "",
        action: "BLOCK" | "ALLOW" = "ALLOW",
        priority: number = 0, // 1 to 10
        protocol: string = "ANY"
    ) {
        this.ruleID = ruleID;
        this.targetIP = targetIP;
        this.action = action;
        this.priority = priority;
        this.protocol = protocol;
    }

    public incrementHit() {
        this.hitCount++;
    }
}

// ============================================================
//  CLASS: LogEntry
// ============================================================
export class LogEntry {
    public timestamp: string;
    public action: "BLOCKED" | "ALLOWED";
    public sourceIP: string;
    public port: number;
    public ruleID: string;
    public priority: number;
    public protocol: string;

    constructor(
        timestamp: string,
        action: "BLOCKED" | "ALLOWED",
        sourceIP: string,
        port: number,
        ruleID: string,
        priority: number,
        protocol: string
    ) {
        this.timestamp = timestamp;
        this.action = action;
        this.sourceIP = sourceIP;
        this.port = port;
        this.ruleID = ruleID;
        this.priority = priority;
        this.protocol = protocol;
    }
}

// ============================================================
//  DATA STRUCTURE 1: QUEUE (Linear — Circular Array)
// ============================================================
export class PacketQueue {
    private data: (Packet | null)[] = new Array(MAX_PACKETS).fill(null);
    private frontIdx: number = 0;
    private rearIdx: number = 0;
    private count: number = 0;

    public push(p: Packet): boolean {
        if (this.count === MAX_PACKETS) {
            return false;
        }
        this.data[this.rearIdx] = p;
        this.rearIdx = (this.rearIdx + 1) % MAX_PACKETS;
        this.count++;
        return true;
    }

    public pop(): Packet | null {
        if (this.empty()) {
            return null;
        }
        const p = this.data[this.frontIdx];
        this.data[this.frontIdx] = null;
        this.frontIdx = (this.frontIdx + 1) % MAX_PACKETS;
        this.count--;
        return p;
    }

    public front(): Packet | null {
        if (this.empty()) return null;
        return this.data[this.frontIdx];
    }

    public empty(): boolean {
        return this.count === 0;
    }

    public size(): number {
        return this.count;
    }

    // Helper for visualizer to inspect the queue elements in FIFO order
    public getElements(): Packet[] {
        const result: Packet[] = [];
        let curr = this.frontIdx;
        for (let i = 0; i < this.count; i++) {
            const item = this.data[curr];
            if (item) result.push(item);
            curr = (curr + 1) % MAX_PACKETS;
        }
        return result;
    }

    // Direct state getters
    public getFrontIdx() { return this.frontIdx; }
    public getRearIdx() { return this.rearIdx; }
    public getCapacity() { return MAX_PACKETS; }
    public getRawArray() { return this.data; }
}

// ============================================================
//  DATA STRUCTURE 2: HASH TABLE (Chaining Collision Resolution)
// ============================================================
export class HashNode {
    public key: string;
    public value: Rule;
    public next: HashNode | null;

    constructor(
        key: string,
        value: Rule,
        next: HashNode | null = null
    ) {
        this.key = key;
        this.value = value;
        this.next = next;
    }
}

export class HashTable {
    private table: (HashNode | null)[] = new Array(HASH_TABLE_SIZE).fill(null);
    private itemCount: number = 0;

    // Matches the C++ polynomial rolling hash algorithm exactly
    public hashFunction(ip: string): number {
        let hash = 0;
        const prime = 31;
        let multiplier = 1;

        for (let i = 0; i < ip.length; i++) {
            const charCode = ip.charCodeAt(i);
            hash = (hash + (charCode - 32 + 1) * multiplier) % HASH_TABLE_SIZE;
            multiplier = (multiplier * prime) % HASH_TABLE_SIZE;
        }
        return (hash + HASH_TABLE_SIZE) % HASH_TABLE_SIZE;
    }

    public insert(ip: string, rule: Rule): void {
        const idx = this.hashFunction(ip);
        let curr = this.table[idx];

        // Update if IP already has a rule
        while (curr !== null) {
            if (curr.key === ip) {
                curr.value = rule;
                return;
            }
            curr = curr.next;
        }

        // Prepend to chain
        const newNode = new HashNode(ip, rule);
        newNode.next = this.table[idx];
        this.table[idx] = newNode;
        this.itemCount++;
    }

    public search(ip: string): Rule | null {
        const idx = this.hashFunction(ip);
        let curr = this.table[idx];
        while (curr !== null) {
            if (curr.key === ip) {
                return curr.value;
            }
            curr = curr.next;
        }
        return null;
    }

    public remove(ip: string): boolean {
        const idx = this.hashFunction(ip);
        let curr = this.table[idx];
        let prev: HashNode | null = null;

        while (curr !== null) {
            if (curr.key === ip) {
                if (prev !== null) {
                    prev.next = curr.next;
                } else {
                    this.table[idx] = curr.next;
                }
                this.itemCount--;
                return true;
            }
            prev = curr;
            curr = curr.next;
        }
        return false;
    }

    public getCount(): number {
        return this.itemCount;
    }

    // Helper to get structured buckets for display
    public getBuckets(): { index: number; chain: Rule[] }[] {
        const list: { index: number; chain: Rule[] }[] = [];
        for (let i = 0; i < HASH_TABLE_SIZE; i++) {
            const chain: Rule[] = [];
            let curr = this.table[i];
            while (curr !== null) {
                chain.push(curr.value);
                curr = curr.next;
            }
            if (chain.length > 0) {
                list.push({ index: i, chain });
            }
        }
        return list;
    }

    // Helper to check if a bucket has elements
    public getRawTable() {
        return this.table;
    }

    public hashFunctionWithTrace(ip: string): {
        steps: { char: string; charCode: number; termValue: number; intermediateHash: number; multiplier: number }[];
        finalIndex: number;
    } {
        const steps: { char: string; charCode: number; termValue: number; intermediateHash: number; multiplier: number }[] = [];
        let hash = 0;
        const prime = 31;
        let multiplier = 1;

        for (let i = 0; i < ip.length; i++) {
            const char = ip[i];
            const charCode = ip.charCodeAt(i);
            const val = charCode - 32 + 1;
            const term = (val * multiplier) % HASH_TABLE_SIZE;
            hash = (hash + term) % HASH_TABLE_SIZE;
            
            steps.push({
                char,
                charCode,
                termValue: term,
                intermediateHash: hash,
                multiplier
            });
            
            multiplier = (multiplier * prime) % HASH_TABLE_SIZE;
        }
        
        const finalIndex = (hash + HASH_TABLE_SIZE) % HASH_TABLE_SIZE;
        return { steps, finalIndex };
    }

    public searchWithTrace(ip: string): {
        hashIndex: number;
        checkedKeys: string[];
        matchedRule: Rule | null;
    } {
        const hashIndex = this.hashFunction(ip);
        const checkedKeys: string[] = [];
        let curr = this.table[hashIndex];
        
        while (curr !== null) {
            checkedKeys.push(curr.key);
            if (curr.key === ip) {
                return { hashIndex, checkedKeys, matchedRule: curr.value };
            }
            curr = curr.next;
        }
        return { hashIndex, checkedKeys, matchedRule: null };
    }
}

// ============================================================
//  DATA STRUCTURE 3: MAX-HEAP (Rule Priority Queue)
// ============================================================
export class MaxHeap {
    private heap: Rule[] = [];

    private heapifyUp(idx: number): void {
        while (idx > 0) {
            const parent = Math.floor((idx - 1) / 2);
            if (this.heap[idx].priority > this.heap[parent].priority) {
                const temp = this.heap[idx];
                this.heap[idx] = this.heap[parent];
                this.heap[parent] = temp;
                idx = parent;
            } else {
                break;
            }
        }
    }

    private heapifyDown(idx: number): void {
        const size = this.heap.length;
        while (true) {
            const left = 2 * idx + 1;
            const right = 2 * idx + 2;
            let largest = idx;

            if (left < size && this.heap[left].priority > this.heap[largest].priority) {
                largest = left;
            }
            if (right < size && this.heap[right].priority > this.heap[largest].priority) {
                largest = right;
            }

            if (largest !== idx) {
                const temp = this.heap[idx];
                this.heap[idx] = this.heap[largest];
                this.heap[largest] = temp;
                idx = largest;
            } else {
                break;
            }
        }
    }

    public push(rule: Rule): boolean {
        if (this.heap.length >= MAX_RULES) {
            return false;
        }
        this.heap.push(rule);
        this.heapifyUp(this.heap.length - 1);
        return true;
    }

    public top(): Rule | null {
        if (this.empty()) return null;
        return this.heap[0];
    }

    public pop(): Rule | null {
        if (this.empty()) return null;
        const root = this.heap[0];
        if (this.heap.length === 1) {
            this.heap = [];
        } else {
            this.heap[0] = this.heap.pop()!;
            this.heapifyDown(0);
        }
        return root;
    }

    public empty(): boolean {
        return this.heap.length === 0;
    }

    public size(): number {
        return this.heap.length;
    }

    public getRawArray(): Rule[] {
        return [...this.heap];
    }

    public pushWithTrace(rule: Rule): HeapTraceStep[] {
        const steps: HeapTraceStep[] = [];
        if (this.heap.length >= MAX_RULES) {
            return steps;
        }
        this.heap.push(rule);
        let idx = this.heap.length - 1;
        steps.push({
            array: [...this.heap],
            comparing: null,
            swapping: null,
            message: `Inserted Rule ${rule.ruleID} at index ${idx} (priority ${rule.priority})`
        });

        while (idx > 0) {
            const parent = Math.floor((idx - 1) / 2);
            steps.push({
                array: [...this.heap],
                comparing: [idx, parent],
                swapping: null,
                message: `Comparing parent index ${parent} (priority ${this.heap[parent].priority}) with child index ${idx} (priority ${this.heap[idx].priority})`
            });

            if (this.heap[idx].priority > this.heap[parent].priority) {
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: [idx, parent],
                    message: `Child priority is higher. Swapping index ${idx} with parent index ${parent}`
                });
                const temp = this.heap[idx];
                this.heap[idx] = this.heap[parent];
                this.heap[parent] = temp;
                
                idx = parent;
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: null,
                    message: `Heap after swap at index ${idx}`
                });
            } else {
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: null,
                    message: `Parent priority is larger/equal. Heap property satisfied.`
                });
                break;
            }
        }
        return steps;
    }

    public popWithTrace(): HeapTraceStep[] {
        const steps: HeapTraceStep[] = [];
        if (this.empty()) return steps;
        
        const root = this.heap[0];
        if (this.heap.length === 1) {
            this.heap = [];
            steps.push({
                array: [],
                comparing: null,
                swapping: null,
                message: `Removed the only rule ${root.ruleID}. Heap is now empty.`
            });
            return steps;
        }

        const last = this.heap.pop()!;
        this.heap[0] = last;
        steps.push({
            array: [...this.heap],
            comparing: null,
            swapping: null,
            message: `Moved last rule ${last.ruleID} to root index 0. Rebuilding heap...`
        });

        let idx = 0;
        const size = this.heap.length;
        while (true) {
            const left = 2 * idx + 1;
            const right = 2 * idx + 2;
            let largest = idx;

            if (left < size) {
                steps.push({
                    array: [...this.heap],
                    comparing: [left, largest],
                    swapping: null,
                    message: `Comparing left child index ${left} (priority ${this.heap[left].priority}) with index ${largest} (priority ${this.heap[largest].priority})`
                });
                if (this.heap[left].priority > this.heap[largest].priority) {
                    largest = left;
                }
            }

            if (right < size) {
                steps.push({
                    array: [...this.heap],
                    comparing: [right, largest],
                    swapping: null,
                    message: `Comparing right child index ${right} (priority ${this.heap[right].priority}) with largest index ${largest} (priority ${this.heap[largest].priority})`
                });
                if (this.heap[right].priority > this.heap[largest].priority) {
                    largest = right;
                }
            }

            if (largest !== idx) {
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: [idx, largest],
                    message: `Swapping index ${idx} with child index ${largest} (higher priority)`
                });
                const temp = this.heap[idx];
                this.heap[idx] = this.heap[largest];
                this.heap[largest] = temp;
                
                idx = largest;
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: null,
                    message: `Heap after swap at index ${idx}`
                });
            } else {
                steps.push({
                    array: [...this.heap],
                    comparing: null,
                    swapping: null,
                    message: `Heap property restored at index ${idx}. Rebuild complete.`
                });
                break;
            }
        }
        return steps;
    }
}

// ============================================================
//  DATA STRUCTURE 4: BST (Binary Search Tree — IP Blocking)
// ============================================================
export class BSTNode {
    public left: BSTNode | null = null;
    public right: BSTNode | null = null;
    public ip: string;
    constructor(ip: string) {
        this.ip = ip;
    }
}

export class BST {
    private root: BSTNode | null = null;

    private insertHelper(node: BSTNode | null, ip: string): BSTNode {
        if (!node) return new BSTNode(ip);
        if (ip < node.ip) {
            node.left = this.insertHelper(node.left, ip);
        } else if (ip > node.ip) {
            node.right = this.insertHelper(node.right, ip);
        }
        return node;
    }

    private searchHelper(node: BSTNode | null, ip: string): boolean {
        if (!node) return false;
        if (ip === node.ip) return true;
        if (ip < node.ip) return this.searchHelper(node.left, ip);
        return this.searchHelper(node.right, ip);
    }

    private inorderHelper(node: BSTNode | null, list: string[]): void {
        if (!node) return;
        this.inorderHelper(node.left, list);
        list.push(node.ip);
        this.inorderHelper(node.right, list);
    }

    public insert(ip: string): void {
        this.root = this.insertHelper(this.root, ip);
    }

    public isBlocked(ip: string): boolean {
        return this.searchHelper(this.root, ip);
    }

    public getSortedBlockedIPs(): string[] {
        const list: string[] = [];
        this.inorderHelper(this.root, list);
        return list;
    }

    public getRoot(): BSTNode | null {
        return this.root;
    }

    public traceSearch(ip: string): { path: string[]; found: boolean } {
        const path: string[] = [];
        let curr = this.root;
        while (curr !== null) {
            path.push(curr.ip);
            if (ip === curr.ip) {
                return { path, found: true };
            }
            if (ip < curr.ip) {
                curr = curr.left;
            } else {
                curr = curr.right;
            }
        }
        return { path, found: false };
    }

    public clear(): void {
        this.root = null;
    }
}

// ============================================================
//  DATA STRUCTURE 5: ARRAY — Log Storage & Custom Sorting
// ============================================================
export class LogManager {
    private logs: LogEntry[] = [];
    public sortMetrics = {
        comparisons: 0,
        swaps: 0,
        timeTakenMs: 0
    };

    public addLog(entry: LogEntry): void {
        if (this.logs.length >= MAX_LOGS) {
            this.logs.shift(); // circular-like pop oldest to prevent page freeze
        }
        this.logs.push(entry);
    }

    public getLogs(): LogEntry[] {
        return [...this.logs];
    }

    public clearLogs(): void {
        this.logs = [];
    }

    // ---- Quick Sort (by Timestamp Ascending) ----
    public sortByTimestamp(): void {
        const t0 = performance.now();
        let comps = 0;
        let swaps = 0;

        const partition = (low: number, high: number): number => {
            const pivot = this.logs[high].timestamp;
            let i = low - 1;
            for (let j = low; j < high; j++) {
                comps++;
                if (this.logs[j].timestamp <= pivot) {
                    i++;
                    swaps++;
                    const temp = this.logs[i];
                    this.logs[i] = this.logs[j];
                    this.logs[j] = temp;
                }
            }
            swaps++;
            const temp = this.logs[i + 1];
            this.logs[i + 1] = this.logs[high];
            this.logs[high] = temp;
            return i + 1;
        };

        const quickSort = (low: number, high: number) => {
            if (low < high) {
                const pi = partition(low, high);
                quickSort(low, pi - 1);
                quickSort(pi + 1, high);
            }
        };

        if (this.logs.length > 1) {
            quickSort(0, this.logs.length - 1);
        }

        const t1 = performance.now();
        this.sortMetrics = {
            comparisons: comps,
            swaps: swaps,
            timeTakenMs: parseFloat((t1 - t0).toFixed(4))
        };
    }

    // ---- Merge Sort (by Severity/Priority Descending) ----
    public sortBySeverity(): void {
        const t0 = performance.now();
        let comps = 0;
        let swaps = 0; // Note: Merge sort uses copies rather than in-place swaps, but we record array writes as swaps/writes

        const merge = (left: number, mid: number, right: number) => {
            const n1 = mid - left + 1;
            const n2 = right - mid;

            const L: LogEntry[] = new Array(n1);
            const R: LogEntry[] = new Array(n2);

            for (let i = 0; i < n1; i++) L[i] = this.logs[left + i];
            for (let j = 0; j < n2; j++) R[j] = this.logs[mid + 1 + j];

            let i = 0, j = 0, k = left;
            // Descending order (highest priority first)
            while (i < n1 && j < n2) {
                comps++;
                if (L[i].priority >= R[j].priority) {
                    swaps++;
                    this.logs[k++] = L[i++];
                } else {
                    swaps++;
                    this.logs[k++] = R[j++];
                }
            }

            while (i < n1) {
                swaps++;
                this.logs[k++] = L[i++];
            }
            while (j < n2) {
                swaps++;
                this.logs[k++] = R[j++];
            }
        };

        const mergeSort = (left: number, right: number) => {
            if (left < right) {
                const mid = Math.floor(left + (right - left) / 2);
                mergeSort(left, mid);
                mergeSort(mid + 1, right);
                merge(left, mid, right);
            }
        };

        if (this.logs.length > 1) {
            mergeSort(0, this.logs.length - 1);
        }

        const t1 = performance.now();
        this.sortMetrics = {
            comparisons: comps,
            swaps: swaps,
            timeTakenMs: parseFloat((t1 - t0).toFixed(4))
        };
    }

    public binarySearchByIP(ip: string): LogEntry[] {
        // Binary search requires sorting by SourceIP first. We will implement quick sort by IP,
        // then perform binary search, returning all matching records.
        
        // 1. Sort logs by source IP ascending
        const partitionIP = (low: number, high: number): number => {
            const pivot = this.logs[high].sourceIP;
            let i = low - 1;
            for (let j = low; j < high; j++) {
                if (this.logs[j].sourceIP <= pivot) {
                    i++;
                    const temp = this.logs[i];
                    this.logs[i] = this.logs[j];
                    this.logs[j] = temp;
                }
            }
            const temp = this.logs[i + 1];
            this.logs[i + 1] = this.logs[high];
            this.logs[high] = temp;
            return i + 1;
        };

        const quickSortIP = (low: number, high: number) => {
            if (low < high) {
                const pi = partitionIP(low, high);
                quickSortIP(low, pi - 1);
                quickSortIP(pi + 1, high);
            }
        };

        if (this.logs.length > 1) {
            quickSortIP(0, this.logs.length - 1);
        }

        // 2. Binary search for first match
        let low = 0;
        let high = this.logs.length - 1;
        let matchIdx = -1;

        while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            if (this.logs[mid].sourceIP === ip) {
                matchIdx = mid;
                break;
            } else if (this.logs[mid].sourceIP < ip) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        if (matchIdx === -1) return [];

        // 3. Collect all matches surrounding the found index (since duplicates exist)
        const results: LogEntry[] = [];
        let l = matchIdx;
        while (l >= 0 && this.logs[l].sourceIP === ip) {
            results.unshift(this.logs[l]);
            l--;
        }
        let r = matchIdx + 1;
        while (r < this.logs.length && this.logs[r].sourceIP === ip) {
            results.push(this.logs[r]);
            r++;
        }

        return results;
    }

    public getBlockedCount(): number {
        return this.logs.filter(l => l.action === "BLOCKED").length;
    }

    public sortByTimestampWithTrace(): SortTraceStep[] {
        const steps: SortTraceStep[] = [];
        const logsCopy = [...this.logs];
        
        const partition = (low: number, high: number): number => {
            const pivot = logsCopy[high].timestamp;
            let i = low - 1;
            for (let j = low; j < high; j++) {
                steps.push({
                    logs: [...logsCopy],
                    comparing: [j, high],
                    swapping: null,
                    message: `Comparing index ${j} (${logsCopy[j].timestamp}) with pivot index ${high} (${pivot})`
                });
                if (logsCopy[j].timestamp <= pivot) {
                    i++;
                    steps.push({
                        logs: [...logsCopy],
                        comparing: null,
                        swapping: [i, j],
                        message: `IP/timestamp <= pivot. Swapping index ${i} with index ${j}`
                    });
                    const temp = logsCopy[i];
                    logsCopy[i] = logsCopy[j];
                    logsCopy[j] = temp;
                }
            }
            steps.push({
                logs: [...logsCopy],
                comparing: null,
                swapping: [i + 1, high],
                message: `Placing pivot at correct position. Swapping index ${i + 1} with index ${high}`
            });
            const temp = logsCopy[i + 1];
            logsCopy[i + 1] = logsCopy[high];
            logsCopy[high] = temp;
            return i + 1;
        };

        const quickSort = (low: number, high: number) => {
            if (low < high) {
                const pi = partition(low, high);
                quickSort(low, pi - 1);
                quickSort(pi + 1, high);
            }
        };

        if (logsCopy.length > 1) {
            quickSort(0, logsCopy.length - 1);
        }
        
        steps.push({
            logs: [...logsCopy],
            comparing: null,
            swapping: null,
            message: `Quick Sort completed!`
        });
        
        return steps;
    }

    public sortBySeverityWithTrace(): SortTraceStep[] {
        const steps: SortTraceStep[] = [];
        const logsCopy = [...this.logs];
        
        const merge = (left: number, mid: number, right: number) => {
            const n1 = mid - left + 1;
            const n2 = right - mid;
            
            const L: LogEntry[] = new Array(n1);
            const R: LogEntry[] = new Array(n2);
            
            for (let i = 0; i < n1; i++) L[i] = logsCopy[left + i];
            for (let j = 0; j < n2; j++) R[j] = logsCopy[mid + 1 + j];
            
            let i = 0, j = 0, k = left;
            while (i < n1 && j < n2) {
                steps.push({
                    logs: [...logsCopy],
                    comparing: [left + i, mid + 1 + j],
                    swapping: null,
                    message: `Comparing priority at left index ${left + i} (P:${L[i].priority}) and right index ${mid + 1 + j} (P:${R[j].priority})`
                });
                if (L[i].priority >= R[j].priority) {
                    steps.push({
                        logs: [...logsCopy],
                        comparing: null,
                        swapping: [k, left + i],
                        message: `Left index is higher/equal. Copying to position ${k}`
                    });
                    logsCopy[k++] = L[i++];
                } else {
                    steps.push({
                        logs: [...logsCopy],
                        comparing: null,
                        swapping: [k, mid + 1 + j],
                        message: `Right index is higher. Copying to position ${k}`
                    });
                    logsCopy[k++] = R[j++];
                }
            }
            
            while (i < n1) {
                steps.push({
                    logs: [...logsCopy],
                    comparing: null,
                    swapping: [k, left + i],
                    message: `Copying remaining element from left index to position ${k}`
                });
                logsCopy[k++] = L[i++];
            }
            while (j < n2) {
                steps.push({
                    logs: [...logsCopy],
                    comparing: null,
                    swapping: [k, mid + 1 + j],
                    message: `Copying remaining element from right index to position ${k}`
                });
                logsCopy[k++] = R[j++];
            }
        };

        const mergeSort = (left: number, right: number) => {
            if (left < right) {
                const mid = Math.floor(left + (right - left) / 2);
                mergeSort(left, mid);
                mergeSort(mid + 1, right);
                merge(left, mid, right);
            }
        };

        if (logsCopy.length > 1) {
            mergeSort(0, logsCopy.length - 1);
        }
        
        steps.push({
            logs: [...logsCopy],
            comparing: null,
            swapping: null,
            message: `Merge Sort completed!`
        });
        
        return steps;
    }

    public getAllowedCount(): number {
        return this.logs.filter(l => l.action === "ALLOWED").length;
    }
}

// ============================================================
//  CLASS: Firewall (Orchestrates All Data Structures)
// ============================================================
export class Firewall {
    public packetQueue = new PacketQueue();
    public ruleTable = new HashTable();
    public ruleHeap = new MaxHeap();
    public ipTree = new BST();
    public logManager = new LogManager();

    public totalProcessed = 0;

    constructor() {}

    private getFormattedTimestamp(): string {
        const now = new Date();
        const yyyy = now.getFullYear();
        const mm = String(now.getMonth() + 1).padStart(2, '0');
        const dd = String(now.getDate()).padStart(2, '0');
        const hh = String(now.getHours()).padStart(2, '0');
        const min = String(now.getMinutes()).padStart(2, '0');
        const sec = String(now.getSeconds()).padStart(2, '0');
        return `${yyyy}-${mm}-${dd} ${hh}:${min}:${sec}`;
    }

    // Returns details of which step determined the decision
    public processSinglePacket(pkt: Packet): { action: "ALLOWED" | "BLOCKED"; ruleID: string; priority: number; checkStep: string } {
        const srcIP = pkt.sourceIP;
        let action: "ALLOW" | "BLOCK" | null = null;
        let ruleID = "DEFAULT";
        let pri = 0;
        let checkStep = "Default Policy";

        // STEP 1: Hash Table — exact IP match
        const hashMatch = this.ruleTable.search(srcIP);
        if (hashMatch) {
            hashMatch.incrementHit();
            action = hashMatch.action;
            ruleID = hashMatch.ruleID;
            pri = hashMatch.priority;
            checkStep = `Hash Table exact match (${hashMatch.ruleID})`;
        }

        // STEP 2: BST — IP range blocked check
        if (action === null && this.ipTree.isBlocked(srcIP)) {
            action = "BLOCK";
            ruleID = "BST-BLOCK";
            pri = 8;
            checkStep = "BST Blocked IP index check";
        }

        // STEP 3: Fallback default
        if (action === null) {
            action = "ALLOW";
            ruleID = "DEFAULT";
            pri = 0;
            checkStep = "Default Allow Rule (No blocks match)";
        }

        const decision: "ALLOWED" | "BLOCKED" = (action === "BLOCK") ? "BLOCKED" : "ALLOWED";
        const entry = new LogEntry(
            this.getFormattedTimestamp(),
            decision,
            srcIP,
            pkt.port,
            ruleID,
            pri,
            pkt.protocol
        );

        this.logManager.addLog(entry);
        this.totalProcessed++;
        return { action: decision, ruleID, priority: pri, checkStep };
    }

    // Processes next packet in queue, returning it and the decision details
    public processNext(): { 
        packet: Packet; 
        decision: { 
            action: "ALLOWED" | "BLOCKED"; 
            ruleID: string; 
            priority: number; 
            checkStep: string; 
        }; 
    } | null {
        if (this.packetQueue.empty()) return null;
        const pkt = this.packetQueue.pop()!;
        const decision = this.processSinglePacket(pkt);
        return { packet: pkt, decision };
    }

    public addRule(r: Rule): void {
        this.removeRule(r.targetIP); // Prevent duplicate entries in heap and BST
        this.ruleTable.insert(r.targetIP, r);
        this.ruleHeap.push(r);
        if (r.action === "BLOCK") {
            this.ipTree.insert(r.targetIP);
        }
    }

    public removeRule(ip: string): boolean {
        // Remove from hash table
        const removed = this.ruleTable.remove(ip);
        if (removed) {
            // Rebuild Heap (in-place)
            const oldRules = this.ruleHeap.getRawArray();
            this.ruleHeap = new MaxHeap();
            for (const rule of oldRules) {
                if (rule.targetIP !== ip) {
                    this.ruleHeap.push(rule);
                }
            }

            // Rebuild BST (BST delete can be complicated, we can rebuild it)
            const oldRulesForBST = this.ruleHeap.getRawArray();
            this.ipTree.clear();
            for (const rule of oldRulesForBST) {
                if (rule.action === "BLOCK") {
                    this.ipTree.insert(rule.targetIP);
                }
            }
        }
        return removed;
    }

    // Load defaults matches C++ loadRules / loadPackets
    public loadDefaults(): void {
        // Rules
        const r1 = new Rule("R001", "192.168.1.10", "BLOCK", 9, "ANY");
        const r2 = new Rule("R002", "8.8.8.8", "ALLOW", 5, "UDP");
        const r3 = new Rule("R003", "172.16.0.1", "BLOCK", 8, "TCP");
        const r4 = new Rule("R004", "45.33.32.156", "BLOCK", 10, "HTTP");
        const r5 = new Rule("R005", "10.0.0.5", "ALLOW", 3, "TCP");
        const r6 = new Rule("R006", "203.0.113.50", "BLOCK", 7, "ANY");
        const r7 = new Rule("R007", "192.168.1.50", "BLOCK", 6, "ANY");

        const rules = [r1, r2, r3, r4, r5, r6, r7];
        for (const rule of rules) {
            this.addRule(rule);
        }

        // Packets
        const packets = [
            new Packet("192.168.1.10", "10.0.0.5", 8080, "TCP", 1024),
            new Packet("8.8.8.8", "192.168.1.1", 53, "UDP", 256),
            new Packet("172.16.0.1", "10.0.0.1", 443, "TCP", 512),
            new Packet("45.33.32.156", "192.168.0.1", 80, "HTTP", 2048),
            new Packet("10.0.0.5", "8.8.8.8", 443, "TCP", 768),
            new Packet("203.0.113.50", "10.0.0.2", 22, "ANY", 128),
            new Packet("192.168.1.50", "172.16.0.5", 3306, "ANY", 4096),
            new Packet("1.1.1.1", "10.0.0.1", 80, "HTTP", 300)
        ];
        for (const p of packets) {
            this.packetQueue.push(p);
        }
    }
}
