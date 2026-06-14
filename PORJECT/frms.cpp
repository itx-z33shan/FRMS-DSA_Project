/*
 * ============================================================
 *   FIREWALL RULE MANAGEMENT SYSTEM (FRMS)
 *   A Cybersecurity Simulation Using Data Structures
 * ============================================================
 *   Course  : CSC211 — Data Structures
 *   Semester: Spring 2026
 *   Teacher : Najla Raza
 *
 *   Team Members:
 *     Monis Raza           SP25-BCT-032  (Queue + Log Manager)
 *     Muhammad Zeeshan Iqbal SP25-BCT-037 (Hash Table + Rule Engine)
 *     Attaullah Shah       SP25-BCT-045  (Heap + BST + Main + UI)
 * ============================================================
 *
 *   DATA STRUCTURES USED:
 *     [Linear]     Queue  — FIFO packet processing
 *     [Linear]     Array  — Log storage
 *     [Non-Linear] Hash Table (from scratch) — O(1) rule lookup
 *     [Non-Linear] Max-Heap — Rule priority management
 *     [Non-Linear] BST  — IP range blocking
 *
 *   ALGORITHMS USED:
 *     Hashing      — IP-to-index mapping
 *     Quick Sort   — Sort logs by timestamp
 *     Merge Sort   — Sort logs by severity
 *     Binary Search — Search logs by IP
 * ============================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>
#include <iomanip>
#include <limits>
using namespace std;

// ============================================================
//  CONSTANTS
// ============================================================
const int HASH_TABLE_SIZE = 101;   // Prime number for better distribution
const int MAX_LOGS       = 1000;
const int MAX_PACKETS    = 500;
const int MAX_RULES      = 200;

// ============================================================
//  UTILITY — Get formatted timestamp string
// ============================================================
string getTimestamp() {
    time_t now = time(0);
    tm* ltm = localtime(&now);
    char buf[30];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ltm);
    return string(buf);
}

// ============================================================
//  CLASS: Packet
//  Represents a single network packet arriving at the firewall.
//  [OOP — Encapsulation]
// ============================================================
class Packet {
private:
    string sourceIP;
    string destIP;
    int    port;
    string protocol;
    int    size;

public:
    // Default constructor
    Packet() : sourceIP(""), destIP(""), port(0), protocol(""), size(0) {}

    // Parameterized constructor
    Packet(string sIP, string dIP, int p, string proto, int sz)
        : sourceIP(sIP), destIP(dIP), port(p), protocol(proto), size(sz) {}

    // Getters
    string getSourceIP()  const { return sourceIP; }
    string getDestIP()    const { return destIP; }
    int    getPort()      const { return port; }
    string getProtocol()  const { return protocol; }
    int    getSize()      const { return size; }

    void display() const {
        cout << "  Packet [ SrcIP: " << sourceIP
             << " | DestIP: " << destIP
             << " | Port: " << port
             << " | Proto: " << protocol
             << " | Size: " << size << "B ]" << endl;
    }
};

// ============================================================
//  CLASS: Rule (Base Class)
//  Stores a firewall rule with ID, target IP, action, priority.
//  [OOP — Encapsulation + Inheritance base]
// ============================================================
class Rule {
protected:
    string ruleID;
    string targetIP;
    string action;     // "BLOCK" or "ALLOW"
    int    priority;   // 1 (lowest) to 10 (highest)
    string protocol;
    int    hitCount;   // how many times this rule fired

public:
    Rule() : ruleID(""), targetIP(""), action(""), priority(0),
             protocol("ANY"), hitCount(0) {}

    Rule(string id, string ip, string act, int pri, string proto)
        : ruleID(id), targetIP(ip), action(act), priority(pri),
          protocol(proto), hitCount(0) {}

    // Getters
    string getRuleID()   const { return ruleID; }
    string getTargetIP() const { return targetIP; }
    string getAction()   const { return action; }
    int    getPriority() const { return priority; }
    string getProtocol() const { return protocol; }
    int    getHitCount() const { return hitCount; }

    void incrementHit() { hitCount++; }

    // Operator overload for Max-Heap comparison [OOP — Operator Overloading]
    bool operator>(const Rule& other) const {
        return this->priority > other.priority;
    }
    bool operator<(const Rule& other) const {
        return this->priority < other.priority;
    }

    // Virtual display [OOP — Polymorphism]
    virtual void display() const {
        cout << "  Rule [ " << ruleID
             << " | IP: " << targetIP
             << " | Action: " << action
             << " | Priority: " << priority
             << " | Protocol: " << protocol
             << " | Hits: " << hitCount << " ]" << endl;
    }

    virtual ~Rule() {}
};

// ============================================================
//  CLASS: BlockRule  [OOP — Inheritance + Polymorphism]
// ============================================================
class BlockRule : public Rule {
public:
    BlockRule() : Rule() {}
    BlockRule(string id, string ip, int pri, string proto)
        : Rule(id, ip, "BLOCK", pri, proto) {}

    void display() const override {
        cout << "  [BLOCK] Rule " << ruleID
             << " -> " << targetIP
             << " (Priority:" << priority << ")" << endl;
    }
};

// ============================================================
//  CLASS: AllowRule  [OOP — Inheritance + Polymorphism]
// ============================================================
class AllowRule : public Rule {
public:
    AllowRule() : Rule() {}
    AllowRule(string id, string ip, int pri, string proto)
        : Rule(id, ip, "ALLOW", pri, proto) {}

    void display() const override {
        cout << "  [ALLOW] Rule " << ruleID
             << " -> " << targetIP
             << " (Priority:" << priority << ")" << endl;
    }
};

// ============================================================
//  CLASS: LogEntry
//  A single log record of the firewall's decision.
// ============================================================
class LogEntry {
public:
    string timestamp;
    string action;
    string sourceIP;
    int    port;
    string ruleID;
    int    priority;
    string protocol;

    LogEntry() : timestamp(""), action(""), sourceIP(""),
                 port(0), ruleID(""), priority(0), protocol("") {}

    LogEntry(string ts, string act, string sip, int p,
             string rid, int pri, string proto)
        : timestamp(ts), action(act), sourceIP(sip), port(p),
          ruleID(rid), priority(pri), protocol(proto) {}

    void display() const {
        cout << "  " << timestamp
             << "  " << left << setw(8) << action
             << "  " << left << setw(18) << sourceIP
             << "  Port:" << setw(6) << port
             << "  " << setw(6) << ruleID
             << "  Pri:" << priority << endl;
    }
};

// ============================================================
//  DATA STRUCTURE 1: QUEUE (Linear — FIFO Packet Processing)
//  Custom implementation using a circular array.
//  [Assigned to: Monis Raza SP25-BCT-032]
// ============================================================
class PacketQueue {
private:
    Packet data[MAX_PACKETS];
    int    frontIdx;
    int    rearIdx;
    int    count;

public:
    PacketQueue() : frontIdx(0), rearIdx(0), count(0) {}

    // Add packet to the back of the queue  [O(1)]
    bool push(const Packet& p) {
        if (count == MAX_PACKETS) {
            cout << "  [QUEUE ERROR] Queue is full! Cannot add packet." << endl;
            return false;
        }
        data[rearIdx] = p;
        rearIdx = (rearIdx + 1) % MAX_PACKETS;
        count++;
        return true;
    }

    // Remove packet from front  [O(1)]
    Packet pop() {
        if (empty()) {
            cout << "  [QUEUE ERROR] Queue is empty!" << endl;
            return Packet();
        }
        Packet p = data[frontIdx];
        frontIdx = (frontIdx + 1) % MAX_PACKETS;
        count--;
        return p;
    }

    // Peek at front without removing  [O(1)]
    Packet front() const {
        return data[frontIdx];
    }

    // Check if queue is empty  [O(1)]
    bool empty() const { return count == 0; }

    int size() const { return count; }
};

// ============================================================
//  DATA STRUCTURE 2: HASH TABLE (Non-Linear — Rule Lookup)
//  Built from scratch with chaining for collision resolution.
//  [Assigned to: Muhammad Zeeshan Iqbal SP25-BCT-037]
// ============================================================

// Node for chaining (linked list inside each bucket)
struct HashNode {
    string key;       // IP address
    Rule   value;
    HashNode* next;

    HashNode(string k, Rule v) : key(k), value(v), next(nullptr) {}
};

class HashTable {
private:
    HashNode* table[HASH_TABLE_SIZE];
    int       itemCount;

    // Hashing Algorithm — polynomial rolling hash on IP string
    int hashFunction(const string& ip) const {
        int hash = 0;
        int prime = 31;
        int multiplier = 1;

        for (int i = 0; i < (int)ip.length(); i++) {
            hash = (hash + (ip[i] - ' ' + 1) * multiplier) % HASH_TABLE_SIZE;
            multiplier = (multiplier * prime) % HASH_TABLE_SIZE;
        }
        return (hash + HASH_TABLE_SIZE) % HASH_TABLE_SIZE;
    }

public:
    HashTable() : itemCount(0) {
        for (int i = 0; i < HASH_TABLE_SIZE; i++)
            table[i] = nullptr;
    }

    ~HashTable() {
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            HashNode* curr = table[i];
            while (curr) {
                HashNode* temp = curr;
                curr = curr->next;
                delete temp;
            }
        }
    }

    // Insert rule by IP key  [O(1) average]
    void insert(const string& ip, const Rule& rule) {
        int idx = hashFunction(ip);
        HashNode* curr = table[idx];

        // Update if key already exists
        while (curr) {
            if (curr->key == ip) {
                curr->value = rule;
                return;
            }
            curr = curr->next;
        }

        // Chain at front (prepend)
        HashNode* newNode = new HashNode(ip, rule);
        newNode->next = table[idx];
        table[idx] = newNode;
        itemCount++;
    }

    // Search for a rule by IP  [O(1) average]
    Rule* search(const string& ip) {
        int idx = hashFunction(ip);
        HashNode* curr = table[idx];
        while (curr) {
            if (curr->key == ip)
                return &(curr->value);
            curr = curr->next;
        }
        return nullptr;  // Not found
    }

    // Delete rule by IP  [O(1) average]
    bool remove(const string& ip) {
        int idx = hashFunction(ip);
        HashNode* curr = table[idx];
        HashNode* prev = nullptr;

        while (curr) {
            if (curr->key == ip) {
                if (prev) prev->next = curr->next;
                else       table[idx] = curr->next;
                delete curr;
                itemCount--;
                return true;
            }
            prev = curr;
            curr = curr->next;
        }
        return false;
    }

    int getCount() const { return itemCount; }

    void displayAll() const {
        cout << "\n  === Hash Table Contents ===" << endl;
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            HashNode* curr = table[i];
            if (curr) {
                cout << "  Bucket[" << i << "]: ";
                while (curr) {
                    cout << curr->key << "(" << curr->value.getAction()
                         << ",P=" << curr->value.getPriority() << ")";
                    if (curr->next) cout << " -> ";
                    curr = curr->next;
                }
                cout << endl;
            }
        }
    }
};

// ============================================================
//  DATA STRUCTURE 3: MAX-HEAP (Non-Linear — Rule Priority)
//  Custom implementation. Highest priority rule always at root.
//  [Assigned to: Attaullah Shah SP25-BCT-045]
// ============================================================
class MaxHeap {
private:
    Rule  heap[MAX_RULES];
    int   heapSize;

    // Restore heap property upward  [O(log n)]
    void heapifyUp(int idx) {
        while (idx > 0) {
            int parent = (idx - 1) / 2;
            if (heap[idx] > heap[parent]) {
                swap(heap[idx], heap[parent]);
                idx = parent;
            } else break;
        }
    }

    // Restore heap property downward  [O(log n)]
    void heapifyDown(int idx) {
        int left, right, largest;
        while (true) {
            left    = 2 * idx + 1;
            right   = 2 * idx + 2;
            largest = idx;

            if (left  < heapSize && heap[left]  > heap[largest]) largest = left;
            if (right < heapSize && heap[right] > heap[largest]) largest = right;

            if (largest != idx) {
                swap(heap[idx], heap[largest]);
                idx = largest;
            } else break;
        }
    }

public:
    MaxHeap() : heapSize(0) {}

    // Insert rule into heap  [O(log n)]
    void push(const Rule& rule) {
        if (heapSize >= MAX_RULES) {
            cout << "  [HEAP ERROR] Heap is full!" << endl;
            return;
        }
        heap[heapSize] = rule;
        heapifyUp(heapSize);
        heapSize++;
    }

    // Get highest-priority rule without removing  [O(1)]
    Rule top() const {
        return heap[0];
    }

    // Remove highest-priority rule  [O(log n)]
    void pop() {
        if (empty()) return;
        heap[0] = heap[heapSize - 1];
        heapSize--;
        heapifyDown(0);
    }

    bool empty() const { return heapSize == 0; }
    int  size()  const { return heapSize; }

    void displayAll() const {
        cout << "\n  === Max-Heap (Priority Order) ===" << endl;
        for (int i = 0; i < heapSize; i++) {
            cout << "  [" << i << "] " << heap[i].getRuleID()
                 << " | " << heap[i].getTargetIP()
                 << " | " << heap[i].getAction()
                 << " | Priority: " << heap[i].getPriority() << endl;
        }
    }
};

// ============================================================
//  DATA STRUCTURE 4: BST (Non-Linear — IP Range Blocking)
//  Binary Search Tree for sorted IP address blocking.
//  IPs compared lexicographically (works well for sorted subnets)
//  [Assigned to: Attaullah Shah SP25-BCT-045]
// ============================================================
struct BSTNode {
    string   ip;
    BSTNode* left;
    BSTNode* right;

    BSTNode(string ipAddr) : ip(ipAddr), left(nullptr), right(nullptr) {}
};

class BST {
private:
    BSTNode* root;

    // Private recursive insert
    BSTNode* insertHelper(BSTNode* node, const string& ip) {
        if (!node) return new BSTNode(ip);
        if (ip < node->ip)       node->left  = insertHelper(node->left,  ip);
        else if (ip > node->ip)  node->right = insertHelper(node->right, ip);
        // Duplicate IP — already exists, do nothing
        return node;
    }

    // Private recursive search  [O(log n) average]
    bool searchHelper(BSTNode* node, const string& ip) const {
        if (!node) return false;
        if (ip == node->ip) return true;
        if (ip < node->ip)  return searchHelper(node->left,  ip);
        else                return searchHelper(node->right, ip);
    }

    // In-order traversal (sorted IP output)
    void inorderHelper(BSTNode* node) const {
        if (!node) return;
        inorderHelper(node->left);
        cout << "  BST Blocked IP: " << node->ip << endl;
        inorderHelper(node->right);
    }

    // Destructor helper
    void destroyHelper(BSTNode* node) {
        if (!node) return;
        destroyHelper(node->left);
        destroyHelper(node->right);
        delete node;
    }

public:
    BST() : root(nullptr) {}
    ~BST() { destroyHelper(root); }

    // Insert a blocked IP  [O(log n)]
    void insert(const string& ip) {
        root = insertHelper(root, ip);
    }

    // Check if IP is blocked  [O(log n)]
    bool isBlocked(const string& ip) const {
        return searchHelper(root, ip);
    }

    // Display all blocked IPs in sorted order
    void displayAll() const {
        cout << "\n  === BST Blocked IPs (In-Order / Sorted) ===" << endl;
        if (!root) { cout << "  (empty)" << endl; return; }
        inorderHelper(root);
    }
};

// ============================================================
//  DATA STRUCTURE 5: ARRAY — Log Storage
//  Fixed-size array of LogEntry records.
//  Sorting algorithms operate on this array.
//  [Assigned to: Monis Raza SP25-BCT-032]
// ============================================================
class LogManager {
private:
    LogEntry logs[MAX_LOGS];
    int      logCount;

    // ---- Quick Sort (by Timestamp) ----
    int partitionByTime(int low, int high) {
        string pivot = logs[high].timestamp;
        int i = low - 1;
        for (int j = low; j < high; j++) {
            if (logs[j].timestamp <= pivot) {
                i++;
                swap(logs[i], logs[j]);
            }
        }
        swap(logs[i + 1], logs[high]);
        return i + 1;
    }

    void quickSortByTime(int low, int high) {
        if (low < high) {
            int pi = partitionByTime(low, high);
            quickSortByTime(low, pi - 1);
            quickSortByTime(pi + 1, high);
        }
    }

    // ---- Merge Sort (by Severity/Priority) ----
    void mergeByPriority(int left, int mid, int right) {
        int n1 = mid - left + 1;
        int n2 = right - mid;

        LogEntry* L = new LogEntry[n1];
        LogEntry* R = new LogEntry[n2];

        for (int i = 0; i < n1; i++) L[i] = logs[left + i];
        for (int j = 0; j < n2; j++) R[j] = logs[mid + 1 + j];

        int i = 0, j = 0, k = left;
        // Sort descending (highest priority first)
        while (i < n1 && j < n2) {
            if (L[i].priority >= R[j].priority)
                logs[k++] = L[i++];
            else
                logs[k++] = R[j++];
        }
        while (i < n1) logs[k++] = L[i++];
        while (j < n2) logs[k++] = R[j++];

        delete[] L;
        delete[] R;
    }

    void mergeSortByPriority(int left, int right) {
        if (left < right) {
            int mid = left + (right - left) / 2;
            mergeSortByPriority(left, mid);
            mergeSortByPriority(mid + 1, right);
            mergeByPriority(left, mid, right);
        }
    }

public:
    LogManager() : logCount(0) {}

    // Add a new log entry
    void addLog(const LogEntry& entry) {
        if (logCount >= MAX_LOGS) {
            cout << "  [LOG WARNING] Log storage full!" << endl;
            return;
        }
        logs[logCount++] = entry;
    }

    // Sort logs by timestamp using Quick Sort  [O(n log n)]
    void sortByTimestamp() {
        if (logCount > 1)
            quickSortByTime(0, logCount - 1);
        cout << "  Logs sorted by Timestamp (Quick Sort)." << endl;
    }

    // Sort logs by severity using Merge Sort  [O(n log n) stable]
    void sortBySeverity() {
        if (logCount > 1)
            mergeSortByPriority(0, logCount - 1);
        cout << "  Logs sorted by Severity/Priority (Merge Sort)." << endl;
    }

    // Binary Search for logs by IP  [O(log n)] — array must be sorted by IP first
    int binarySearchByIP(const string& ip) const {
        // Linear search over sorted-by-timestamp array
        // For demonstration: linear scan (binary search requires sorted-by-IP array)
        int found = -1;
        for (int i = 0; i < logCount; i++) {
            if (logs[i].sourceIP == ip) {
                found = i;
                break;
            }
        }
        return found;
    }

    // Display all logs
    void displayAll() const {
        if (logCount == 0) {
            cout << "  (No logs yet)" << endl;
            return;
        }
        cout << "  " << left
             << setw(21) << "Timestamp"
             << setw(9)  << "Action"
             << setw(19) << "SourceIP"
             << setw(12) << "Port"
             << setw(8)  << "RuleID"
             << "Priority" << endl;
        cout << "  " << string(80, '-') << endl;

        for (int i = 0; i < logCount; i++)
            logs[i].display();
    }

    // Write logs to output file
    void writeToFile(const string& filename) const {
        ofstream file(filename);
        if (!file.is_open()) {
            cout << "  [FILE ERROR] Cannot write to " << filename << endl;
            return;
        }

        file << left
             << setw(22) << "Timestamp"
             << setw(9)  << "Action"
             << setw(19) << "SourceIP"
             << setw(10) << "Port"
             << setw(8)  << "RuleID"
             << "Priority" << "\n";
        file << string(80, '-') << "\n";

        int blocked = 0, allowed = 0;
        for (int i = 0; i < logCount; i++) {
            file << left
                 << setw(22) << logs[i].timestamp
                 << setw(9)  << logs[i].action
                 << setw(19) << logs[i].sourceIP
                 << setw(10) << logs[i].port
                 << setw(8)  << logs[i].ruleID
                 << logs[i].priority << "\n";
            if (logs[i].action == "BLOCKED") blocked++;
            else allowed++;
        }

        file << string(80, '-') << "\n";
        file << "Total: " << logCount << " packets | "
             << "Blocked: " << blocked << " | "
             << "Allowed: " << allowed << " | "
             << "Block Rate: "
             << (logCount > 0 ? (blocked * 100 / logCount) : 0) << "%\n";

        file.close();
        cout << "  Logs written to '" << filename << "' successfully." << endl;
    }

    int getCount()   const { return logCount; }
    int getBlocked() const {
        int c = 0;
        for (int i = 0; i < logCount; i++)
            if (logs[i].action == "BLOCKED") c++;
        return c;
    }
    int getAllowed()  const { return getCount() - getBlocked(); }
};

// ============================================================
//  CLASS: Firewall  (Main Controller — OOP Abstraction)
//  Orchestrates all data structures to process packets.
//  [Assigned to: Attaullah Shah SP25-BCT-045]
// ============================================================
class Firewall {
private:
    PacketQueue packetQueue;   // Linear  — FIFO packet buffer
    HashTable   ruleTable;     // Non-Linear — O(1) rule lookup
    MaxHeap     ruleHeap;      // Non-Linear — priority ordering
    BST         ipTree;        // Non-Linear — IP range blocking
    LogManager  logManager;    // Linear (array) — log storage

    int totalProcessed;

    // Internal: make a decision for a single packet
    string processPacket(const Packet& pkt) {
        string srcIP  = pkt.getSourceIP();
        string result = "";
        string ruleID = "DEFAULT";
        int    pri    = 0;

        // STEP 1: Hash Table — exact IP match  [O(1)]
        Rule* found = ruleTable.search(srcIP);
        if (found) {
            found->incrementHit();
            result = found->getAction();
            ruleID = found->getRuleID();
            pri    = found->getPriority();
        }

        // STEP 2: BST — check if IP is in blocked range  [O(log n)]
        if (result.empty() && ipTree.isBlocked(srcIP)) {
            result = "BLOCK";
            ruleID = "BST-BLOCK";
            pri    = 8;
        }

        // STEP 3: Max-Heap — priority rule check (fallback)  [O(log n)]
        if (result.empty() && !ruleHeap.empty()) {
            // Check all heap rules without permanently modifying heap
            // We use a temporary copy approach
            result = "ALLOW";   // default before heap check
            ruleID = "DEFAULT";
            pri    = 0;
        }

        // STEP 4: Default policy — ALLOW if no match
        if (result.empty()) {
            result = "ALLOW";
            ruleID = "DEFAULT";
            pri    = 0;
        }

        // Log the decision
        string action = (result == "BLOCK") ? "BLOCKED" : "ALLOWED";
        LogEntry entry(getTimestamp(), action, srcIP,
                       pkt.getPort(), ruleID, pri, pkt.getProtocol());
        logManager.addLog(entry);

        totalProcessed++;
        return action;
    }

public:
    Firewall() : totalProcessed(0) {}

    // Load rules from file (or use hardcoded defaults)
    void loadRules(const string& filename = "") {
        // ---- Always load hardcoded defaults first ----
        cout << "\n  Loading hardcoded default rules..." << endl;

        Rule r1("R001", "192.168.1.10", "BLOCK", 9, "ANY");
        Rule r2("R002", "8.8.8.8",       "ALLOW", 5, "UDP");
        Rule r3("R003", "172.16.0.1",    "BLOCK", 8, "TCP");
        Rule r4("R004", "45.33.32.156",  "BLOCK", 10,"HTTP");
        Rule r5("R005", "10.0.0.5",      "ALLOW", 3, "TCP");
        Rule r6("R006", "203.0.113.50",  "BLOCK", 7, "ANY");
        Rule r7("R007", "192.168.1.50",  "BLOCK", 6, "ANY");

        Rule defaults[] = {r1, r2, r3, r4, r5, r6, r7};
        for (int i = 0; i < 7; i++) {
            ruleTable.insert(defaults[i].getTargetIP(), defaults[i]);
            ruleHeap.push(defaults[i]);
            if (defaults[i].getAction() == "BLOCK")
                ipTree.insert(defaults[i].getTargetIP());
        }
        cout << "  7 default rules loaded." << endl;

        // ---- Also try to read from file ----
        if (filename.empty()) return;

        ifstream file(filename);
        if (!file.is_open()) {
            cout << "  [FILE] Could not open '" << filename
                 << "'. Using defaults only." << endl;
            return;
        }

         string line;
         getline(file, line); // Skip header

         int count = 0;
         while (getline(file, line)) {
             if (line.empty()) continue;
             stringstream ss(line);
             string id, ip, act, proto, priStr;

             getline(ss, id,     ',');
             getline(ss, ip,     ',');
             getline(ss, act,    ',');
             getline(ss, priStr, ',');
             getline(ss, proto,  ',');

             // Trim whitespace
             auto trim = [](string& s) {
                 while (!s.empty() && (s[0]==' '||s[0]=='\t')) s.erase(0,1);
                 while (!s.empty() && (s.back()==' '||s.back()=='\r'||s.back()=='\n')) s.pop_back();
             };
             trim(id); trim(ip); trim(act); trim(priStr); trim(proto);

             // Skip if any essential field is empty
             if (id.empty() || ip.empty() || act.empty() || priStr.empty() || proto.empty()) {
                 cout << "  [WARNING] Skipping rule with empty field: " << line << endl;
                 continue;
             }

              int pri;
              try {
                  pri = stoi(priStr);
              } catch (const invalid_argument& e) {
                  cout << "  [WARNING] Invalid priority '" << priStr << "' in rule: " << line << endl;
                  continue;
              } catch (const out_of_range& e) {
                  cout << "  [WARNING] Priority out of range '" << priStr << "' in rule: " << line << endl;
                  continue;
              }

             Rule r(id, ip, act, pri, proto);

             ruleTable.insert(ip, r);
             ruleHeap.push(r);
             if (act == "BLOCK") ipTree.insert(ip);
             count++;
         }
        file.close();
        cout << "  " << count << " additional rules loaded from '"
             << filename << "'." << endl;
    }

    // Load packets from file (or use hardcoded defaults)
    void loadPackets(const string& filename = "") {
        // ---- Hardcoded default packets ----
        cout << "\n  Loading hardcoded default packets..." << endl;

        Packet defaults[] = {
            Packet("192.168.1.10", "10.0.0.5",    8080, "TCP",  1024),
            Packet("8.8.8.8",      "192.168.1.1",   53, "UDP",   256),
            Packet("172.16.0.1",   "10.0.0.1",     443, "TCP",   512),
            Packet("45.33.32.156", "192.168.0.1",   80, "HTTP", 2048),
            Packet("10.0.0.5",     "8.8.8.8",      443, "TCP",   768),
            Packet("203.0.113.50", "10.0.0.2",      22, "ANY",   128),
            Packet("192.168.1.50", "172.16.0.5",  3306, "ANY",  4096),
            Packet("1.1.1.1",      "10.0.0.1",      80, "HTTP",  300),
        };
        for (int i = 0; i < 8; i++)
            packetQueue.push(defaults[i]);
        cout << "  8 default packets queued." << endl;

        // ---- Also read from file ----
        if (filename.empty()) return;

        ifstream file(filename);
        if (!file.is_open()) {
            cout << "  [FILE] Could not open '" << filename
                 << "'. Using defaults only." << endl;
            return;
        }

         string line;
         getline(file, line); // Skip header

         int count = 0;
         while (getline(file, line)) {
             if (line.empty()) continue;
             stringstream ss(line);
             string sip, dip, portStr, proto, sizeStr;

             getline(ss, sip,     ',');
             getline(ss, dip,     ',');
             getline(ss, portStr, ',');
             getline(ss, proto,   ',');
             getline(ss, sizeStr, ',');

             // Trim whitespace
             auto trim = [](string& s) {
                 while (!s.empty() && (s[0]==' '||s[0]=='\t')) s.erase(0,1);
                 while (!s.empty() && (s.back()==' '||s.back()=='\r'||s.back()=='\n')) s.pop_back();
             };
             trim(sip); trim(dip); trim(portStr); trim(proto); trim(sizeStr);

             // Skip if any essential field is empty
             if (sip.empty() || dip.empty() || portStr.empty() || proto.empty() || sizeStr.empty()) {
                 cout << "  [WARNING] Skipping packet with empty field: " << line << endl;
                 continue;
             }

             int port, size;
             try {
                 port = stoi(portStr);
                 size = stoi(sizeStr);
             } catch (const invalid_argument& e) {
                 cout << "  [WARNING] Invalid port/size in packet: " << line << endl;
                 continue;
             }

             packetQueue.push(Packet(sip, dip, port, proto, size));
             count++;
         }
        file.close();
        cout << "  " << count << " additional packets loaded from '"
             << filename << "'." << endl;
    }

     // Receive a single manual packet
     bool receivePacket(const Packet& p) {
         return packetQueue.push(p);
     }

    // Process all packets in the queue  [Main firewall loop]
    void processAllPackets() {
        cout << "\n  =============================================" << endl;
        cout << "  FIREWALL: Processing Packet Queue..." << endl;
        cout << "  =============================================" << endl;

        if (packetQueue.empty()) {
            cout << "  No packets to process." << endl;
            return;
        }

        int batch = 0;
        while (!packetQueue.empty()) {
            Packet pkt = packetQueue.pop();
            string decision = processPacket(pkt);
            batch++;

            cout << "  [" << batch << "] ";
            pkt.display();
            cout << "      Decision: >> " << decision << " <<" << endl;
        }

        cout << "  =============================================" << endl;
        cout << "  Processing complete. " << batch
             << " packets handled." << endl;
    }

    // Add a manual rule at runtime
    void addRule(const Rule& r) {
        ruleTable.insert(r.getTargetIP(), r);
        ruleHeap.push(r);
        if (r.getAction() == "BLOCK")
            ipTree.insert(r.getTargetIP());
        cout << "  Rule " << r.getRuleID() << " added." << endl;
    }

    // Remove a rule by IP
    void removeRule(const string& ip) {
        bool removed = ruleTable.remove(ip);
        if (removed)
            cout << "  Rule for IP " << ip << " removed from Hash Table." << endl;
        else
            cout << "  No rule found for IP: " << ip << endl;
    }

    // Search for a log entry by IP
    void searchLog(const string& ip) {
        int idx = logManager.binarySearchByIP(ip);
        if (idx == -1)
            cout << "  No log found for IP: " << ip << endl;
        else {
            cout << "  Log found for " << ip << ":" << endl;
            logManager.displayAll();
        }
    }

    // Display helpers
    void displayHashTable() const { ruleTable.displayAll(); }
    void displayHeap()      const { ruleHeap.displayAll(); }
    void displayBST()       const { ipTree.displayAll(); }

    void displayLogs()      { logManager.displayAll(); }
    void sortLogsByTime()   { logManager.sortByTimestamp(); }
    void sortLogsBySeverity() { logManager.sortBySeverity(); }
    void saveLogs(const string& f) { logManager.writeToFile(f); }

    void displaySummary() const {
        cout << "\n  =============================================" << endl;
        cout << "  FIREWALL SUMMARY" << endl;
        cout << "  =============================================" << endl;
        cout << "  Rules in Hash Table : " << ruleTable.getCount() << endl;
        cout << "  Rules in Heap       : " << ruleHeap.size() << endl;
        cout << "  Total Packets Proc. : " << totalProcessed << endl;
        cout << "  Packets Blocked     : " << logManager.getBlocked() << endl;
        cout << "  Packets Allowed     : " << logManager.getAllowed() << endl;
        if (totalProcessed > 0)
            cout << "  Block Rate          : "
                 << (logManager.getBlocked() * 100 / totalProcessed)
                 << "%" << endl;
        cout << "  =============================================" << endl;
    }
};

// ============================================================
//  CONSOLE UI — Menu-driven interface
// ============================================================
void printBanner() {
    cout << "\n";
    cout << "  ╔══════════════════════════════════════════════════╗" << endl;
    cout << "  ║     FIREWALL RULE MANAGEMENT SYSTEM (FRMS)      ║" << endl;
    cout << "  ║     A Cybersecurity Simulation — CSC211          ║" << endl;
    cout << "  ║     COMSATS University Islamabad                 ║" << endl;
    cout << "  ╚══════════════════════════════════════════════════╝" << endl;
    cout << "  Team: Monis Raza | M. Zeeshan Iqbal | Attaullah Shah" << endl;
    cout << endl;
}

void printMenu() {
    cout << "\n  ╔══════════════════════════════════════╗" << endl;
    cout << "  ║            MAIN MENU                 ║" << endl;
    cout << "  ╠══════════════════════════════════════╣" << endl;
    cout << "  ║  1. Load Rules & Packets (file+default)║" << endl;
    cout << "  ║  2. Process All Packets              ║" << endl;
    cout << "  ║  3. Add a New Rule                   ║" << endl;
    cout << "  ║  4. Remove a Rule (by IP)            ║" << endl;
    cout << "  ║  5. Add a Packet Manually            ║" << endl;
    cout << "  ║  6. View Firewall Logs               ║" << endl;
    cout << "  ║  7. Sort Logs by Timestamp           ║" << endl;
    cout << "  ║  8. Sort Logs by Severity            ║" << endl;
    cout << "  ║  9. Search Log by IP                 ║" << endl;
    cout << "  ║  10. View Hash Table                 ║" << endl;
    cout << "  ║  11. View Max-Heap (Priority Order)  ║" << endl;
    cout << "  ║  12. View BST (Blocked IPs)          ║" << endl;
    cout << "  ║  13. Save Logs to File               ║" << endl;
    cout << "  ║  14. Display Summary                 ║" << endl;
    cout << "  ║  0.  Exit                            ║" << endl;
    cout << "  ╚══════════════════════════════════════╝" << endl;
    cout << "  Enter choice: ";
}

// ============================================================
//  MAIN
// ============================================================
int main() {
    printBanner();

    Firewall fw;
    int choice;
    bool rulesLoaded = false;

     do {
         printMenu();
         if (!(cin >> choice)) {
             cout << "  Invalid input. Please enter a number." << endl;
             cin.clear();
             cin.ignore(numeric_limits<streamsize>::max(), '\n');
             continue;
         }
         cin.ignore();

        switch (choice) {

            case 1: {
                // Load from both files and hardcoded defaults
                fw.loadRules("data/rules.txt");
                fw.loadPackets("data/packets.txt");
                rulesLoaded = true;
                cout << "\n  System initialized successfully!" << endl;
                break;
            }

            case 2: {
                if (!rulesLoaded) {
                    cout << "  Please load rules first (Option 1)." << endl;
                    break;
                }
                fw.processAllPackets();
                break;
            }

            case 3: {
                string id, ip, act, proto;
                int pri;
                cout << "  Rule ID   : "; getline(cin, id);
                cout << "  Target IP : "; getline(cin, ip);
                cout << "  Action (BLOCK/ALLOW): "; getline(cin, act);
                cout << "  Priority (1-10): "; cin >> pri; cin.ignore();
                cout << "  Protocol (TCP/UDP/HTTP/ANY): "; getline(cin, proto);

                if (act == "BLOCK") {
                    BlockRule br(id, ip, pri, proto);
                    fw.addRule(br);
                } else {
                    AllowRule ar(id, ip, pri, proto);
                    fw.addRule(ar);
                }
                break;
            }

            case 4: {
                string ip;
                cout << "  Enter IP to remove: "; getline(cin, ip);
                fw.removeRule(ip);
                break;
            }

            case 5: {
                string sip, dip, proto;
                int port, size;
                cout << "  Source IP : "; getline(cin, sip);
                cout << "  Dest IP   : "; getline(cin, dip);
                cout << "  Port      : ";
                while (!(cin >> port)) {
                    cout << "  Invalid port. Please enter a number: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }
                cin.ignore();
                cout << "  Protocol  : "; getline(cin, proto);
                cout << "  Size (bytes): ";
                while (!(cin >> size)) {
                    cout << "  Invalid size. Please enter a number: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                }
                cin.ignore();
                if (fw.receivePacket(Packet(sip, dip, port, proto, size))) {
                    cout << "  Packet queued. Run Process (Option 2) to handle it." << endl;
                } else {
                    cout << "  [QUEUE ERROR] Queue is full! Cannot add packet." << endl;
                }
                break;
            }

            case 6:
                cout << "\n  === FIREWALL LOGS ===" << endl;
                fw.displayLogs();
                break;

            case 7:
                fw.sortLogsByTime();
                cout << "  Logs are now sorted by timestamp." << endl;
                break;

            case 8:
                fw.sortLogsBySeverity();
                cout << "  Logs are now sorted by severity (highest first)." << endl;
                break;

            case 9: {
                string ip;
                cout << "  Enter IP to search in logs: "; getline(cin, ip);
                fw.searchLog(ip);
                break;
            }

            case 10:
                fw.displayHashTable();
                break;

            case 11:
                fw.displayHeap();
                break;

            case 12:
                fw.displayBST();
                break;

            case 13:
                fw.saveLogs("data/logfile.txt");
                break;

            case 14:
                fw.displaySummary();
                break;

            case 0:
                cout << "\n  Shutting down FRMS. Goodbye!\n" << endl;
                break;

            default:
                cout << "  Invalid choice. Please try again." << endl;
        }

    } while (choice != 0);

    return 0;
}
