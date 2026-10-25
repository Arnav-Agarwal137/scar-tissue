import { readFileSync } from 'node:fs';
import { compileFunction } from 'node:vm';

// Evaluate proposed tool calls only. These commands are NEVER executed.
const policies = [];
const source = readFileSync(new URL('./scar-tissue.mjs', import.meta.url), 'utf8')
  .replace('import { customPolicies, allow, deny, instruct } from "failproofai";', '')
  .replace('import { readFileSync } from "node:fs";', '');
const verdict = decision => reason => ({ decision, ...(reason ? { reason } : {}) });
compileFunction(source, ['customPolicies', 'allow', 'deny', 'instruct', 'readFileSync'])(
  { add: p => policies.push(p) }, verdict('allow'), verdict('deny'), verdict('instruct'), readFileSync);
const demos = {
  kill: ['kill-by-pid-only', 'taskkill /IM node.exe /F', 'taskkill /PID 4242 /F'],
  pipeline: ['keep-the-exit-code', 'pytest | tail -20', 'pytest > run.log 2>&1; rc=$?; tail -20 run.log; echo exit=$rc'],
  outbound: ['approval-before-it-leaves', 'git push origin main', 'git push --dry-run'],
};
const picked = demos[process.argv[2]];
if (!picked) {
  console.error('Usage: node demo.mjs kill|pipeline|outbound');
  process.exitCode = 1;
} else {
  const [name, bad, clean] = picked;
  const policy = policies.find(p => p.name === name);
  for (const [label, cmd] of [['Incident', bad], ['Safe control', clean]]) {
    const result = await policy.fn({ toolName: 'exec_command', toolInput: { cmd } });
    console.log(`${label}: ${cmd}\n${result.decision.toUpperCase()}${result.reason ? ': ' + result.reason : ''}\n`);
  }
}
