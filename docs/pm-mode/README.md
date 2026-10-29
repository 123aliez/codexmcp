# PM 工作流配置

让 Claude（Opus）只负责规划和验收，代码的实现、阅读和测试都通过 `codex` 工具交给 Codex 执行。

| 文件 | 放到哪里 | 作用 |
|---|---|---|
| `skills/codex-delegate/SKILL.md` | `~/.claude/skills/codex-delegate/SKILL.md`（用户级，所有项目通用） | 任务书模板、沙箱选择、返回值解读、验收清单，需要时才加载 |
| `CLAUDE.md` | 追加到项目的 `CLAUDE.md` 或 `~/.claude/CLAUDE.md` | 角色定位和几条铁律，每次会话都会加载。工作区已有自己的规则体系时（如在规则文件里写了 PM 模式），不需要这个文件 |
| `settings.example.json` | 合并进启动 Claude Code 的那个目录下的 `.claude/settings.json` | 免确认调用 `codex` 工具；按扩展名禁止 Claude 直接编辑代码文件 |

## 安装 skill（Linux / macOS）

```bash
mkdir -p ~/.claude/skills/codex-delegate
curl -fsSL https://raw.githubusercontent.com/123aliez/codexmcp/main/docs/pm-mode/skills/codex-delegate/SKILL.md \
  -o ~/.claude/skills/codex-delegate/SKILL.md
```

访问 GitHub 需要代理时，在 `curl` 前加 `https_proxy=http://127.0.0.1:10808`（端口换成你自己的）。更新 skill 时重新执行一遍即可。

## 注意

1. 如果之前按上游 README 往 `~/.claude/CLAUDE.md` 里加过 "Core Instruction for CodeX MCP" 那一段，请删掉。那段要求 Claude 亲自重写代码，和 PM 模式冲突。
2. 权限规则：
   - Claude Code 只认 `Edit(...)` 路径规则，它覆盖 Edit、Write 等所有编辑工具；写 `Write(...)` 永远不会生效。
   - deny 规则拦不住 Claude 通过 Bash 改文件。
   - `allow` 规则要在交互模式下打开一次 `claude`、信任该目录后才生效；`deny` 规则立即生效。
3. Codex 会自动读取项目 git 根目录到工作目录之间的 `AGENTS.md`。编码规范、测试命令写在项目约定文档里，任务书让 Codex 开工前先读，就不用每次重复。
