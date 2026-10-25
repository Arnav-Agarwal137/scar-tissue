#!/usr/bin/env bash
# End-to-end: install the pack into a throwaway project (Codex, project scope, nothing user-wide),
# then send real Codex PreToolUse hook events through the installed failproofai binary
# (the same command that project's .codex/hooks.json runs) and print what it decided. No agent needed.
set -u
PACK="$(cd "$(dirname "$0")" && pwd)/scar-tissue.mjs"
WORK="$(mktemp -d)"
cd "$WORK" && git init -q
failproofai policies -i -c "$PACK" --cli codex --scope project > install.log 2>&1 || { echo "install failed:"; cat install.log; exit 1; }
run() {
  local cmd="$1" ev out rc v
  ev=$(node -e 'console.log(JSON.stringify({hook_event_name:"PreToolUse",session_id:"e2e-demo",cwd:process.cwd(),tool_name:"Bash",tool_input:{command:process.argv[1]},transcript_path:""}))' "$cmd")
  out=$(printf '%s' "$ev" | failproofai --hook pre_tool_use --cli codex --agent-scope project 2>/dev/null); rc=$?
  if printf '%s' "$out" | grep -qiE 'permissionDecision"?: ?"deny|"decision": ?"block'; then v=BLOCKED; elif [ $rc -eq 2 ]; then v=BLOCKED; else v=allowed; fi
  printf '%-8s %-38s %s\n' "$v" "$cmd" "$(printf '%s' "$out" | grep -oE 'because: [^"]{0,90}' | head -1)"
}
run 'taskkill /IM chrome.exe /F'
run 'taskkill /PID 4242 /F'
run 'git add -A'
run 'git add src/app.js'
run 'git reset --hard'
run 'git stash --include-untracked'
run 'rm -rf ~'
run 'rm -rf ./build'
run 'powercfg /h on'
run 'git push origin main'
cd / && rm -rf "$WORK"
