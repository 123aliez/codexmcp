# PM 工作流配置

让 Claude（Opus）只负责规划和验收，代码的实现、阅读和测试都通过 `codex` 工具交给 Codex 执行。

| 文件 | 放到哪里 | 作用 |
|---|---|---|
| `CLAUDE.md` | 追加到项目根目录的 `CLAUDE.md`；想在所有项目生效就放进 `~/.claude/CLAUDE.md` | 角色定位和几条铁律，每次会话都会加载 |
| `skills/codex-delegate/SKILL.md` | `.claude/skills/codex-delegate/SKILL.md`（单个项目）或 `~/.claude/skills/codex-delegate/SKILL.md`（全局） | 任务书模板、沙箱选择、返回值解读、验收清单，需要时才加载 |
| `settings.example.json` | 合并进 `.claude/settings.json` | 免确认调用 `codex` 工具和 git 只读命令，并禁止 Claude 直接编辑 `src/`、`tests/` |

注意：

1. 如果之前按上游 README 往 `~/.claude/CLAUDE.md` 里加过 "Core Instruction for CodeX MCP" 那一段，请删掉。那段要求 Claude 亲自重写代码，和 PM 模式相互冲突。
2. `settings.example.json` 里的 `deny` 路径要按你的项目结构修改。deny 规则只能拦住 Claude 的 Edit / Write 工具，拦不住它通过 Bash 改文件。如果需要更硬的约束，可以只在 `allow` 里放必要的只读命令，其余 Bash 命令保持需要确认。
3. Codex 会自动读取项目根目录的 `AGENTS.md`。把编码规范、测试命令写在那里，任务书就不用每次重复这些内容。
