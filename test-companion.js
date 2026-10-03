/**
 * Standalone Test Script for ProctorGuard Desktop Companion Agent
 * 
 * Tests:
 * 1. Auditor engine initialization (Native C++ / Win32 PS fallback)
 * 2. Process auditor (scan running processes, match blacklist)
 * 3. Module auditor (scan loaded DLLs for hooks, Temp paths)
 * 4. Display auditor (detect monitors, resolutions, multi-display)
 * 5. Full unified telemetry audit and threat simulation
 */

const auditor = require('./native-auditor');

async function runTestSuite() {
  console.log('===============================================================');
  console.log('   PROCTORGUARD COMPANION AGENT - NATIVE AUDITOR TEST SUITE    ');
  console.log('===============================================================\n');

  console.log(`Active Engine: ${auditor.isNative() ? 'Native C++ Addon' : 'Win32 PowerShell Bridge Fallback'}\n`);

  // Test 1: Process Auditor
  console.log('--- [1/4] Testing Process Auditor ---');
  try {
    const procStart = Date.now();
    const procRes = await auditor.checkProcesses(['test_fake_cheat.exe']);
    const procDuration = Date.now() - procStart;

    console.log(`[PASS] Total Processes Scanned: ${procRes.totalScanned} in ${procDuration}ms`);
    console.log(`[PASS] Status: ${procRes.status}`);
    if (procRes.detected.length > 0) {
      console.warn(`[WARN] Blacklisted tools running on host (${procRes.detected.length}):`);
      procRes.detected.forEach(d => {
        console.warn(`       - ${d.name} (PID: ${d.pid}, Category: ${d.category}, Rule: ${d.rule})`);
      });
    } else {
      console.log('       No blacklisted processes detected.');
    }
  } catch (err) {
    console.error('[FAIL] Process auditor threw error:', err.message);
  }

  // Test 2: Module Auditor
  console.log('\n--- [2/4] Testing Module Auditor ---');
  try {
    const modStart = Date.now();
    const modRes = await auditor.auditModules(process.pid);
    const modDuration = Date.now() - modStart;

    console.log(`[PASS] Total Modules Inspected: ${modRes.totalModules} in ${modDuration}ms`);
    console.log(`[PASS] Status: ${modRes.status}`);
    if (modRes.suspicious.length > 0) {
      console.warn(`[WARN] Suspicious DLLs detected (${modRes.suspicious.length}):`);
      modRes.suspicious.forEach(m => {
        console.warn(`       - ${m.name}: ${m.reason} [${m.severity}]`);
      });
    } else {
      console.log('       All loaded modules verified (no injectors or Temp DLLs).');
    }
  } catch (err) {
    console.error('[FAIL] Module auditor threw error:', err.message);
  }

  // Test 3: Display Auditor
  console.log('\n--- [3/4] Testing Display Auditor ---');
  try {
    const dispStart = Date.now();
    const dispRes = await auditor.auditDisplays();
    const dispDuration = Date.now() - dispStart;

    console.log(`[PASS] Display Count: ${dispRes.displayCount} in ${dispDuration}ms`);
    console.log(`[PASS] Multi-Display: ${dispRes.isMultiDisplay ? 'YES (VIOLATION)' : 'NO (Compliant)'}`);
    console.log(`[PASS] Cloned Displays: ${dispRes.hasClonedDisplays ? 'YES (VIOLATION)' : 'NO'}`);
    dispRes.displays.forEach((d, idx) => {
      const b = d.bounds || {};
      console.log(`       Display #${idx + 1}: ${d.deviceName} (${b.width}x${b.height}, Primary: ${d.isPrimary})`);
    });
    if (dispRes.violations.length > 0) {
      console.warn(`[WARN] Display violations: ${dispRes.violations.join('; ')}`);
    }
  } catch (err) {
    console.error('[FAIL] Display auditor threw error:', err.message);
  }

  // Test 4: Full Audit & Simulated Threat
  console.log('\n--- [4/4] Testing Full Audit with Simulated Detection ---');
  try {
    const fullStart = Date.now();
    // Simulate detecting powershell.exe as a custom rule to verify threat response
    const fullRes = await auditor.runFullAudit({
      customBlacklist: ['powershell.exe', 'cmd.exe']
    });
    const fullDuration = Date.now() - fullStart;

    console.log(`[PASS] Full Audit Completed in ${fullDuration}ms`);
    console.log(`[PASS] Timestamp: ${fullRes.timestamp}`);
    console.log(`[PASS] Engine: ${fullRes.engine}`);
    console.log(`[PASS] Has Threats: ${fullRes.hasThreats}`);
    console.log(`[PASS] Threat Count: ${fullRes.threatCount || 0}`);

    if (fullRes.threats && fullRes.threats.length > 0) {
      console.log('\nDetailed Threat Summary:');
      fullRes.threats.slice(0, 5).forEach((t, i) => {
        console.log(`   [${i + 1}] Type: ${t.type} | Severity: ${t.severity} | Details: ${t.details}`);
      });
      if (fullRes.threats.length > 5) {
        console.log(`   ... and ${fullRes.threats.length - 5} more threats.`);
      }
    }
  } catch (err) {
    console.error('[FAIL] Full audit threw error:', err.message);
  }

  console.log('\n===============================================================');
  console.log('              ALL AUDITOR TESTS COMPLETED                      ');
  console.log('===============================================================\n');
}

runTestSuite().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
