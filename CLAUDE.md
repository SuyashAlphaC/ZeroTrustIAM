# ZeroTrustIAM — Claude Instructions

## Token-efficient code analysis

When exploring or analyzing this codebase, **prefer Serena MCP tools over `Read` / `Grep` / `Glob`**. Serena uses LSP to return symbol-level slices instead of whole files, which dramatically reduces context usage.

| Task | Use this | Not this |
|------|----------|----------|
| See what's in a file | `mcp__plugin_serena_serena__get_symbols_overview` | `Read` (entire file) |
| Read one function/class | `mcp__plugin_serena_serena__find_symbol` | `Read` with offset guesswork |
| Find callers / usages | `mcp__plugin_serena_serena__find_referencing_symbols` | `Grep` for the name |
| Regex / text search | `mcp__plugin_serena_serena__search_for_pattern` | `Grep` |
| Locate a file by name | `mcp__plugin_serena_serena__find_file` | `Glob` |

At the start of any coding task in this repo, call `mcp__plugin_serena_serena__initial_instructions` and `mcp__plugin_serena_serena__activate_project` once.

**Fall back to `Read`** only for non-code files (markdown, JSON, YAML, configs) or when you genuinely need a whole file.
