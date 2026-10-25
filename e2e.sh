#!/usr/bin/env bash
# End-to-end: send real Codex PreToolUse hook events through the installed failproofai binary
# (the same command ~/.codex/hooks.json runs) and print what it decided. No agent needed.
cd "$(dirname "$0")"
run() {
  local label="$1" cmd="$2"
  local ev
  ev=$(node -e 'console.log(JSON.stringify({hook_event_name:"PreToolUse",session_id:"e2e-demo",cwd:process.cwd(),tool_name:"Bash",tool_input:{command:process.argv[1]},transcript_path:""}))' "$cmd")
  local out
  out=$(printf '%s' "$ev" | failproofai --hook pre_tool_use --cli codex --agent-scope user 2>/dev/null)
  local rc=$?
  if printf '%s' "$out" | grep -qiE '"(deny|block)"|permissionDecision"?: ?"deny|"decision": ?"block'; then v=BLOCKED; elif [ $rc -eq 2 ]; then v=BLOCKED; else v=allowed; fi
  printf '%-8s %-38s %s\n' "$v" "$cmd" "$(printf '%s' "$out" | tr -d '\n' | head -c 160)"
}
run bad  'taskkill /IM chrome.exe /F'
run good 'taskkill /PID 4242 /F'
run bad  'git add -A'
run good 'git add src/app.js'
run bad  'git reset --hard'
run good 'git stash --include-untracked'
run bad  'rm -rf ~'
run good 'rm -rf ./build'
run bad  'powercfg /h on'
run bad  'git push origin main'
