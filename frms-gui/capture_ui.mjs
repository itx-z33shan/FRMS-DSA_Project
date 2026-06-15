import { chromium } from 'playwright';

const base = 'http://localhost:5173';
const out = 'C:\\Users\\PMLS\\Documents\\PORJECT\\frms-gui\\';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.setViewportSize({ width: 1280, height: 720 });

// 1. Initial load
await page.goto(base, { waitUntil: 'networkidle' });
await page.waitForTimeout(2000);
await page.screenshot({ path: out + 'ss1_initial.png', fullPage: false });
console.log('ss1: initial load done');

// 2. Click Load Defaults
await page.click('button:has-text("Load Defaults")');
await page.waitForTimeout(1500);
await page.screenshot({ path: out + 'ss2_defaults.png', fullPage: false });
console.log('ss2: load defaults done');

// 3. Hash Table tab
await page.click('button:has-text("Hash Table")');
await page.waitForTimeout(800);
await page.screenshot({ path: out + 'ss3_hash.png', fullPage: false });
console.log('ss3: hash tab done');

// 4. Max-Heap tab
await page.click('button:has-text("Max-Heap")');
await page.waitForTimeout(800);
await page.screenshot({ path: out + 'ss4_heap.png', fullPage: false });
console.log('ss4: heap tab done');

// 5. BST tab
await page.click('button:has-text("BST")');
await page.waitForTimeout(800);
await page.screenshot({ path: out + 'ss5_bst.png', fullPage: false });
console.log('ss5: bst tab done');

// 6. Sorting & Logs tab
await page.click('button:has-text("Sorting")');
await page.waitForTimeout(800);
await page.screenshot({ path: out + 'ss6_logs.png', fullPage: false });
console.log('ss6: logs tab done');

// 7. Go back to queue, click Animate Step
await page.click('button:has-text("Queue Buffer")');
await page.waitForTimeout(500);
await page.click('button:has-text("Animate Step")');
await page.waitForTimeout(2500);
await page.screenshot({ path: out + 'ss7_animate.png', fullPage: false });
console.log('ss7: animate step done');

await browser.close();
console.log('All screenshots captured!');
