import { customPolicies, allow, deny, instruct } from "failproofai";
import { readFileSync } from "node:fs";

// One digest-pinned entry; no relative imports. API checked against 1.0.12.
const str = v => typeof v === "string" ? v : "";
const norm = v => str(v).replaceAll("\\", "/");
const shellNames = new Set(["bash", "shell", "shell_command", "exec_command", "powershell", "write_stdin"]);
function command(ctx) {
  if (!shellNames.has(str(ctx?.toolName).toLowerCase())) return "";
  const i = ctx?.toolInput;
  const v = i?.command ?? i?.cmd ?? i?.script ?? i?.chars;
  if (Array.isArray(v)) {
    if (/^(?:.*[\\/])?(?:(?:ba|z|da)?sh|powershell|pwsh)(?:\.exe)?$/i.test(str(v[0]))) {
      const n = v.findIndex(x => /^-(?:[a-z]*c|command)$/i.test(str(x)));
      if (n >= 0) return v.slice(n + 1).map(str).join(" ");
    }
    return v.map(x => /\s/.test(str(x)) ? JSON.stringify(x) : str(x)).join(" ");
  }
  return str(v);
}
// Quoted prose is data, not a command. Preserve Windows backslashes.
function segments(cmd) {
  const out = []; let words = [], word = "", quote = "";
  const flush = () => { if (word) words.push(word); word = ""; };
  for (const c of cmd) {
    if (quote) { if (c === quote) quote = ""; else word += c; }
    else if (c === "'" || c === '"') quote = c;
    else if (/[;|&\n\r]/.test(c)) { flush(); if (words.length) out.push(words); words = []; }
    else if (/\s/.test(c)) flush(); else word += c;
  }
  flush(); if (words.length) out.push(words);
  return out.flatMap(w => {
    if (/^(?:bash|sh|pwsh|powershell)(?:\.exe)?$/i.test(w[0])) {
      const n = w.findIndex(x => /^-(?:[a-z]*c|command)$/i.test(x));
      if (n >= 0) return segments(w.slice(n + 1).join(" "));
    }
    return [w];
  });
}
const exe = w => norm(w[0]).split("/").at(-1).replace(/\.exe$/i, "").toLowerCase();
function gitArgs(w) {
  if (exe(w) !== "git") return [];
  let n = 1;
  while (n < w.length && w[n].startsWith("-")) n += /^(?:-C|-c|--git-dir|--work-tree)$/.test(w[n]) ? 2 : 1;
  return w.slice(n);
}
function commitAll(args) {
  for (let n = 0; n < args.length; n++) {
    const x = args[n];
    if (x === "--") break;
    if (x === "--all" || /^-[qvns]*a/.test(x)) return true;
    if (/^(?:-m|-F|-C|-c|-t|-S|--message|--file|--author|--date|--cleanup|--template|--reuse-message|--reedit-message)$/.test(x)) n++;
  }
  return false;
}
function humanText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter(x => x && ["text", "input_text"].includes(x.type)).map(x => str(x.text)).join("\n");
}
function lastHuman(ctx) {
  try {
    const path = ctx?.session?.transcriptPath;
    if (typeof path !== "string" || !path) return "";
    let last = "";
    for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
      if (!line.trim()) continue;
      let r; try { r = JSON.parse(line); } catch { return ""; }
      if (r.type === "user" && r.message?.role === "user" && !r.isMeta) {
        const t = humanText(r.message.content); if (t) last = t;
      } else if (r.type === "response_item" && r.payload?.type === "message" && r.payload.role === "user") {
        const t = humanText(r.payload.content); if (t) last = t;
      } else if (r.type === "event_msg" && r.payload?.type === "user_message") last = str(r.payload.message);
    }
    return last;
  } catch { return ""; }
}
function approved(ctx) {
  const t = lastHuman(ctx);
  if (/\b(?:no|not|never|don't|do not|without|unapproved)\b/i.test(t)) return false;
  return /\b(?:yes|approve|approved|go ahead|send it|push it|ship it|confirm)\b/i.test(t);
}
function register(name, category, description, check) {
  customPolicies.add({ name, description, category, defaultEnabled: true,
    match: { events: ["PreToolUse"] },
    fn: ctx => {
      try { return check(ctx, command(ctx)) ?? allow(); }
      catch { return allow(); } // Engine exceptions fail open: malformed contexts are tested.
    },
  });
}
register("kill-by-pid-only", "Process", "Name-based kills took down unrelated sessions and apps.", (ctx, cmd) => {
  const ws = segments(cmd);
  if (ws.some(w => ["pkill", "killall"].includes(exe(w)) ||
    (exe(w) === "taskkill" && w.some(x => /^\/im$/i.test(x))) ||
    (exe(w) === "stop-process" && w.some(x => /^-name$/i.test(x)))) ||
    (/\bGet-Process\b[^|;\n]*\|\s*Stop-Process\b/i.test(cmd) && ws.some(w => exe(w) === "get-process" && !w.some(x => /^-id$/i.test(x)))))
    return deny("A name-based kill can stop someone else's session. Instead: use taskkill /PID <n> /F for a PID you started.");
});
register("commit-by-path", "Git", "Bulk staging committed another session's unfinished work.", (ctx, cmd) => {
  if (segments(cmd).some(w => {
    const [op, ...a] = gitArgs(w);
    return (op === "add" && a.some(x => ["-A", "--all", "."].includes(x))) ||
      (op === "commit" && commitAll(a));
  })) return deny("Bulk staging includes parallel work. Instead: read git status, then git add <paths you changed> and commit those paths.");
});
register("no-rollback-on-shared-tree", "Git", "A rollback erased a parallel writer's work.", (ctx, cmd) => {
  if (segments(cmd).some(w => {
    const [op, ...a] = gitArgs(w);
    return (op === "reset" && a.includes("--hard")) ||
      (op === "clean" && a.some(x => /^-[^-]*f/.test(x) || x === "--force")) ||
      (op === "checkout" && a.includes("--") && a.includes(".")) || (op === "restore" && a.includes("."));
  })) return deny("Rollback can erase another writer's changes. Instead: use git stash --include-untracked to preserve the shared tree.");
});
register("keep-the-exit-code", "Shell", "A pipeline reported tail's success instead of the test failure.", (ctx, cmd) => {
  const runsProducer = segments(cmd).some(w => /^(?:pytest|make)$/.test(exe(w)) ||
    (exe(w) === "npm" && (w[1] === "test" || (w[1] === "run" && w[2] === "build"))) ||
    (exe(w) === "cargo" && /^(?:test|build)$/.test(w[1])) ||
    (/^python3?$/.test(exe(w)) && w.slice(1).some(x => /train/.test(x))));
  const producerPipe = /(?:\bpytest\b|\bnpm\s+(?:test|run\s+build)\b|\bcargo\s+(?:test|build)\b|\bpython3?\b[^;|&\n]*train|\bmake\b)[^;&\n]*\|\s*(?:tail|head|grep)\b/i;
  if (runsProducer && producerPipe.test(cmd))
    return instruct("The pipe hides the producer's exit code. Instead: use > run.log 2>&1; rc=$?; tail -20 run.log; echo exit=$rc (PowerShell: capture $LASTEXITCODE immediately).");
});
const secret = /sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const envFile = p => /(?:^|\/)\.env(?:\.local)?$/i.test(norm(p));
register("no-secret-in-files", "Secrets", "A live credential was written into a tracked source file.", (ctx, cmd) => {
  const msg = "A live-looking secret would enter source control. Instead: put it in a gitignored .env or .env.local; never git add .env* files.";
  if (segments(cmd).some(w => { const [op, ...a] = gitArgs(w); return op === "add" && a.some(p => /(?:^|\/)\.env[^/]*$/i.test(norm(p))); })) return deny(msg);
  const i = ctx?.toolInput ?? {}, tool = str(ctx?.toolName).toLowerCase();
  if (["write", "edit", "apply_patch"].includes(tool)) {
    const patch = str(i.patch ?? i.input ?? i.patch_text);
    if (patch) for (const s of patch.split(/(?=^\*\*\* (?:Add|Update) File: )/m)) {
      const target = s.match(/^\*\*\* (?:Add|Update) File: (.+)$/m)?.[1];
      const added = s.split(/\r?\n/).filter(l => l.startsWith("+") && !l.startsWith("+++")).join("\n");
      if (secret.test(added) && !envFile(target)) return deny(msg);
    }
    if (secret.test(str(i.content) + str(i.new_string) + str(i.new_text)) && !envFile(i.file_path ?? i.path)) return deny(msg);
  }
  if (secret.test(cmd)) {
    const targets = [...cmd.matchAll(/(?:>{1,2}\s*|(?:Set-Content|Add-Content|Out-File)\s+(?:(?:-Path|-LiteralPath|-FilePath)\s+)?)(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))/gi)].map(m => m[1] ?? m[2] ?? m[3]);
    if (targets.some(p => !envFile(p))) return deny(msg);
  }
});
function outward(w) {
  const e = exe(w), a = w.slice(1), g = gitArgs(w);
  if ((g[0] === "push" || (["npm", "failproofai"].includes(e) && a[0] === "publish")) && !a.includes("--dry-run")) return true;
  if (e === "gh" && ((a[0] === "pr" && ["create", "merge"].includes(a[1])) || (a[0] === "release" && a[1] === "create"))) return true;
  if (["curl", "invoke-webrequest", "iwr"].includes(e)) {
    let write = false;
    const urls = [];
    for (let n = 0; n < a.length; n++) {
      const x = a[n];
      if (/^(?:-X|--request|-Method)$/i.test(x)) { write ||= /^(?:POST|PUT|DELETE)$/i.test(a[++n]); continue; }
      if (/^-X(?:POST|PUT|DELETE)$|^--request=(?:POST|PUT|DELETE)$/i.test(x)) { write = true; continue; }
      if (/^(?:--data(?:-raw|-binary|-urlencode)?|--json|-d)$/i.test(x)) { write = true; n++; continue; }
      if (/^(?:--data(?:-raw|-binary|-urlencode)?|--json)=|^-d.+/i.test(x)) { write = true; continue; }
      if (/^(?:-H|--header|-o|--output|-u|--user|-Body|-ContentType)$/i.test(x)) { n++; continue; }
      if (/^https?:\/\//i.test(x)) urls.push(x);
      else if (/^--url=/.test(x)) urls.push(x.slice(6));
    }
    if (write && (!urls.length || urls.some(x => { try { return !["localhost", "127.0.0.1", "[::1]"].includes(new URL(x).hostname); } catch { return true; } }))) return true;
  }
  return false;
}
register("approval-before-it-leaves", "Outbound", "A draft nearly left the laptop before its owner reviewed it.", (ctx, cmd) => {
  if (segments(cmd).some(outward) && !approved(ctx)) return deny("This action leaves the laptop or changes a remote service. Instead: show the finished thing and ask for explicit approval, then retry.");
});
register("close-needs-both-words", "Process", "Stopping media was mistaken for closing the whole browser.", (ctx, cmd) => {
  const closing = segments(cmd).some(w =>
    (["taskkill", "stop-process"].includes(exe(w)) && w.some(x => /^(?:chrome|msedge|firefox|explorer|WindowsTerminal|Code)(?:\.exe)?$/i.test(x))) ||
    (exe(w) === "get-process" && /\bGet-Process\b[^|;\n]*\|\s*Stop-Process\b/i.test(cmd) && w.some(x => /^(?:chrome|msedge|firefox|explorer|WindowsTerminal|Code)(?:\.exe)?$/i.test(x))) ||
    (exe(w) === "wmctrl" && w.includes("-c")) || (exe(w) === "osascript" && w.some(x => /\bquit\b/i.test(x))));
  const t = lastHuman(ctx);
  if (closing && !(/\b(?:close|quit|exit|kill|shut)\b/i.test(t) && /\b(?:window|tab|browser|chrome|app)\b/i.test(t) && !/\b(?:don't|do not|never)\b/i.test(t)))
    return deny("Stopping media does not authorize closing an app. Instead: pause the media or ask which window to close.");
});
register("no-backslash-heredoc", "Shell", "Escapes inside a heredoc silently corrupted a patch.", (ctx, cmd) => {
  const re = /\b(?:python3?|node)\s+(?:-\s+)?<<-?\s*['"]?(\w+)['"]?[^\n]*\n([\s\S]*?)(?:\n\1\b|$)/g;
  for (const m of cmd.matchAll(re)) if (/\\[nrbt\\]/.test(m[2])) return instruct("The interpreter can reinterpret backslash escapes in this heredoc. Instead: write the script to a file, then run it.");
});
register("never-let-it-sleep", "System", "An overnight job died when laptop sleep was re-enabled.", (ctx, cmd) => {
  if (segments(cmd).some(w => exe(w) === "powercfg" && (
    w.some((x, n) => /^(?:\/h|-h|-hibernate|\/hibernate)$/i.test(x) && /^on$/i.test(w[n + 1])) ||
    w.some((x, n) => /^[-/]?standby-timeout-(?:ac|dc)$/i.test(x) && /^\d+$/.test(w[n + 1]) && Number(w[n + 1]) > 0) ||
    (w.some(x => /^lidaction$/i.test(x)) && /^(?:1|0x0*1)$/i.test(w.at(-1)))
  ))) return deny("Enabling sleep can kill long-running jobs. Instead: leave power settings alone and ask the owner.");
});
// Browser tools expose intended actions as labels instead of shell commands.
const browserTool = /^mcp__.*(?:chrome|browser|playwright|puppeteer)/i;
const irreversible = /\b(send|submit|publish|post|delete|remove|pay|purchase|buy|place order|checkout|confirm|transfer|merge)\b/i;
function browserFields(ctx) {
  if (!browserTool.test(str(ctx?.toolName))) return null;
  const i = ctx?.toolInput ?? {};
  return {
    action: str(i.action) + " " + str(ctx.toolName),
    text: str(i.text ?? i.value),
    url: str(i.url),
    intent: [i.action_summary, i.element, i.description, i.query].map(str).join(" "),
    js: str(i.text ?? i.function ?? i.script ?? i.code),
  };
}
function luhn(s) {
  let sum = 0, alternate = false;
  for (let n = s.length - 1; n >= 0; n--) {
    let digit = Number(s[n]);
    if (alternate) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit; alternate = !alternate;
  }
  return sum % 10 === 0;
}
register("browser-click-to-send-needs-approval", "Browser agents", "A browser action sent an unreviewed draft or committed an irreversible change.", ctx => {
  const f = browserFields(ctx);
  if (f && /click|key|type|form|press|select|submit/i.test(f.action) && irreversible.test(f.intent) && !approved(ctx))
    return deny("This browser action cannot be taken back (" + f.intent.slice(0, 80) + "). Instead: show a screenshot of the finished form or draft, ask for approval, and act only after the person approves.");
});
register("browser-never-types-secrets", "Browser agents", "A credential or card number was typed into a web page.", ctx => {
  const f = browserFields(ctx);
  if (!f || !/type|form_input/i.test(f.action) || !f.text) return;
  const digits = f.text.replace(/[\s-]/g, "");
  if (secret.test(f.text) || (/^\d{13,19}$/.test(digits) && luhn(digits)) || /\b(?:password|passcode|pin|cvv|otp)\b/i.test(f.intent))
    return deny("That looks like a secret (key, card number or password). Instead: ask the person to type it themselves or use their password manager.");
});
register("browser-no-personal-data-in-urls", "Browser agents", "Personal identifiers in a URL leaked into history, logs and referrers.", ctx => {
  const f = browserFields(ctx);
  if (!f || !f.url.includes("?")) return;
  const query = f.url.slice(f.url.indexOf("?") + 1).split("#")[0];
  // URLSearchParams decodes percent escapes and form-encoded spaces defensively.
  const values = [...new URLSearchParams(query)].flat().join(" ");
  if (/[\w.+-]+@[\w-]+\.[\w.]+/.test(values) || /(?:\+?\d[\d -]{9,}\d)/.test(values))
    return deny("This URL puts personal data in history, logs and referrers. Instead: open the page and enter the identifier in its form field.");
});
register("browser-no-native-dialogs", "Browser agents", "A native dialog froze the browser driver.", ctx => {
  const f = browserFields(ctx);
  if (!f) return;
  if (/javascript|evaluate/i.test(str(ctx.toolName)) && /\b(?:alert|confirm|prompt)\s*\(/.test(f.js))
    return deny("alert/confirm/prompt can freeze the page and browser driver. Instead: use console.log and read the console.");
  if (/click/i.test(f.action) && /(?:paperclip|attach file|choose file|browse files|file picker|\bprint\b|save as)/i.test(f.intent))
    return deny("That opens a native OS dialog the browser tool cannot drive. Instead: use the file-upload tool on the hidden file input, or a browser PDF/download tool for print or save.");
});
function dangerousTarget(p) {
  p = norm(p).replace(/\/+$/, "") || "/";
  return /^(?:\/|~|\$HOME|\$env:USERPROFILE|\$env:HOME|%USERPROFILE%|[a-z]:|\.\.|\*)$/i.test(p) ||
    /^[a-z]:\/Users\/[^/]+$/i.test(p) || /^\/home\/[^/]+$/.test(p);
}
register("no-blind-force", "Shell", "A broad force-delete threatened files outside the task.", (ctx, cmd) => {
  if (segments(cmd).some(w => {
    const e = exe(w), a = w.slice(1);
    if (e === "rm") {
      const flags = a.filter(x => x.startsWith("-")).join(" ");
      return /(?:-[^-\s]*r|--recursive)/.test(flags) && /(?:-[^-\s]*f|--force)/.test(flags) && a.some(x => !x.startsWith("-") && dangerousTarget(x));
    }
    return e === "remove-item" && a.some(x => /^-recurse$/i.test(x)) && a.some(x => /^-force$/i.test(x)) && a.some(dangerousTarget);
  })) return deny("A broad force-delete can destroy shared files. Instead: list the specific path you created, verify it, then delete only that path.");
});
