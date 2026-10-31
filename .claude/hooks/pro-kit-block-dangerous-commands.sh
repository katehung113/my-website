#!/bin/bash
# pro-kit: 攔截不可逆的危險指令（PreToolUse hook）
# 讀 stdin 的 JSON，取出 tool_name / tool_input.command，比對危險指令樣式；
# 比對到就回傳 deny 決策，否則 exit 0 交回正常權限流程判斷。

input=$(cat)

# 用 node 解析 JSON（這台機器沒裝 jq，但有 node）
parsed=$(printf '%s' "$input" | node -e '
let data = "";
process.stdin.on("data", c => data += c);
process.stdin.on("end", () => {
  try {
    const j = JSON.parse(data);
    const cmd = (j.tool_input && (j.tool_input.command || j.tool_input.script)) || "";
    process.stdout.write(JSON.stringify({ tool_name: j.tool_name || "", command: cmd }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ tool_name: "", command: "" }));
  }
});
' 2>/dev/null)

command=$(printf '%s' "$parsed" | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{try{process.stdout.write(JSON.parse(d).command||"")}catch(e){}})' 2>/dev/null)

if [ -z "$command" ]; then
  exit 0
fi

# 危險指令樣式（呼應 settings.json 的 deny 清單精神：不可逆、破壞性操作）
pattern='(^|[;&|[:space:]])rm([[:space:]]+-[a-zA-Z]*)*[[:space:]]|rm -rf|rm -fr|rmdir |Remove-Item([[:space:]].*-(Recurse|Force))+|(^|[[:space:]])del |(^|[[:space:]])erase |(^|[[:space:]])rd |sudo |(^|[[:space:]])dd[[:space:]]|mkfs|diskutil (erase|partitionDisk|deleteVolume)|chmod[[:space:]]+(-R[[:space:]]+)?777|git reset[[:space:]].*--hard|git push[[:space:]].*(--force|-f([[:space:]]|$))|git clean[[:space:]].*-f|git branch[[:space:]].*-D|shutdown|reboot|truncate[[:space:]]|Format-Volume|Clear-Disk|Remove-Partition|Stop-Computer|Restart-Computer|diskpart|cmd /c (rd|del)|: *>'

if printf '%s' "$command" | grep -qiE "$pattern"; then
  node -e '
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "pro-kit 安全守則：這是不可逆的破壞性指令，已被攔截。請改用可還原的做法（例如刪檔案用 trash 或移到資源回收筒），或先跟用戶確認。"
    }
  }));
  '
  exit 0
fi

exit 0
