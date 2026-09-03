Status: Reference

# Plan & coordination workflow

A live plan is a **dated file** in `docs/plans/`. A **parent GitHub issue**
(label `plan`) with **one closeable sub-issue per slice** (label `slice`)
coordinates state on top of it. The file is the design; the issues are the
handles. Nothing restates another.

Worked example: [docs/plans/odf-encryption-detection-2026-09-01.md](plans/odf-encryption-detection-2026-09-01.md) → parent [#1](https://github.com/Slurp9187/odf-crypto/issues/1), slices [#2](https://github.com/Slurp9187/odf-crypto/issues/2)–[#7](https://github.com/Slurp9187/odf-crypto/issues/7).

## Surfaces

| Surface | Source of truth for | Where |
|---|---|---|
| **Plan file** | design, predicates, slice list, gotchas | `docs/plans/<feature>-<yyyy-mm-dd>.md` |
| **Parent issue** | the arc handle — pointer to the file, close-out | one issue, label `plan` |
| **Slice issues** | claimable work, each with its own close condition | sub-issues of the parent, label `slice` |

GitHub’s native roll-up on the parent (`completed / total`) is the snapshot.
**Read it; never type a slice count into a body or this file.** Those numbers
go stale.

Filter: `label:plan` for parents, `label:slice` for work items.

## Plan file

- Dated: `docs/plans/<feature>-<yyyy-mm-dd>.md` (author date).
- Written so another agent executes without re-designing.
- Carries `Status:` as a terminal or planned stamp, not a live kanban.
- The slice table in the file is the **design** of the slices (what / done when).
  Filed issues are the **coordination**. When a slice is filed, do not also keep
  a checklist of those same slices on the parent.

## Filing procedure

**One plan → one parent → one sub-issue per slice**, at any size. Actionable
work is never a checkbox line on the parent.

**Order is fixed:** open the parent, read its number, then file the children.
A child title is prefixed with that number because a bare `S1` collides across
arcs and identifies nothing in search, a notification, or a commit message.

### 0. Labels

Create once per repo if missing:

```bash
gh label create plan  --description "Parent plan issue for an arc" --color 0E8A16
gh label create slice --description "Closeable slice of a plan parent" --color 1D76DB
```

### 1. Parent (`plan`)

```bash
gh issue create --label plan --title "<arc title>" --body-file parent.md
```

Parent body carries **only** what is not a slice:

- pointer to the plan file
- goal and out-of-scope (so a cold session does not start decrypting)
- **close when:** every slice sub-issue is closed, plus any arc-level close-out
- a slice table **as placeholders only until filed**; after filing, replace
  placeholder names with `#N` links (the children already exist — this is
  navigation, not a second checklist)

No task list that duplicates the children. No invented board.

### 2. Slices (`slice`)

For each row in the plan’s slice table:

```bash
gh issue create --parent <PARENT> --label slice \
  --title "<PARENT>-S<n>: <what the slice does>" \
  --body-file slice.md
```

Title form: `1-S1: Stage A/B types, URI tables, two-stage classify`.
Use `--parent`. Do **not** hand-write GraphQL or REST `/sub_issues`.

### 3. Slice body — closeable

Every slice must be finishable without reopening the design. Required sections:

| Section | What it is |
|---|---|
| **Parent / plan** | `#<parent>` and the plan heading / slice id |
| **Do** | concrete work; name the types, fixtures, or predicates |
| **Close when** | observable evidence (tests, fixtures, recorded URIs). If gated (corpus, another slice), say the gate |
| **Not this slice** | the neighbouring slices, so scope cannot creep |

A slice that cannot be closed as written is not filed yet — fix the plan first.

**Attachment test:** *when this arc closes, does that issue close too?* No →
not a sub-issue. Deferred work and decisions that gate more than one arc stay
free-standing and are **linked**, not attached.

### 4. Verify

```bash
gh issue view <PARENT> --json title,labels,subIssues \
  -q '{title,labels:[.labels[].name],kids:[.subIssues.nodes[]|{number,title}]}'
```

Every child title starts with `<PARENT>-S`. Parent has `plan` only. Children
have `slice` only.

## Slice quality (from #1)

These are the bars the detection arc used. Keep them:

- **DoD is a fixture or a run**, not “implement §N”.
- **Blocked-on** is named (S2 blocked on S1; S6 blocked on a corpus).
- **Negative space** is named (no decrypt, no origin detector).
- A gated slice (S6) stays **open** until the gate is real. Do not close it
  with a TODO.

## Commands worth keeping

```bash
# roll-up — read, do not retype
gh issue view 1 --json subIssuesSummary \
  -q '"\(.subIssuesSummary.completed)/\(.subIssuesSummary.total) — \(.subIssuesSummary.percentCompleted)%"'

# still open
gh issue view 1 --json subIssues \
  -q '[.subIssues.nodes[] | select(.state=="OPEN") | "#\(.number)"] | join(" ")'

# what a PR will actually close - GitHub's parse, not the body text
gh pr view 17 --json closingIssuesReferences \
  -q '[.closingIssuesReferences[] | "#\(.number)"] | join(" ")'

# attach later
gh issue edit 1 --add-sub-issue 8
gh issue edit 8 --parent 1
```

`subIssuesSummary` is flat (`.subIssuesSummary.total`). `subIssues` wraps
`.subIssues.nodes[]`. A bare `.subIssues[]` fails in a way that looks like an
empty arc.

Native `gh` only. If GraphQL quota is exhausted (`gh api rate_limit -q
.resources.graphql`), wait and re-verify with `gh issue view --json subIssues`.
Do not leave a REST-only attach as the record.

## Closing from a PR or a commit

GitHub parses a closer as `KEYWORD #N` and links **only the first reference after
each keyword**. To close several issues, repeat the keyword for every one. This
applies identically to a **pull request body** and to a **commit message** — the
two differ only in *when* they fire.

| Written | What GitHub does |
|---|---|
| `Closes #10, closes #11, closes #12` | all three close |
| `Closes #10` / `Closes #11` on their own lines | all close |
| `Closes #10, #11, #12` | only #10 closes; the rest are plain mentions |
| `Closes #10, #11 and #12` | same — only the first `#N` counts |
| `Closes #10-#15`, `#10–#15`, `#10..#15` | a range is not an issue reference; **nothing** is linked |

A comma after a valid closer is punctuation, not a new closer. The documented
multi-issue form is `Resolves #10, resolves #123, resolves octo-org/octo-repo#100`.

**When each fires.** A PR-body closer fires when the PR merges into the default
branch. A commit-message closer fires when that commit *reaches* the default
branch — immediately for a direct push (how the detection arc landed), or at
merge for a branch. Rebase-merge preserves the individual messages, so their
closers survive; squash-merge composes one body from them, and an author who
edits that body can drop a closer without noticing. On a non-default branch,
neither fires.

**Where to put the closer.** A slice is closed by hand, with a comment carrying
the evidence that closed it — not by a keyword in a commit nobody reads
afterwards. Keep `Closes #<parent>` in the PR body so the
arc handle closes on merge, and let commits *mention* issues without keywords —
`Implement password decrypt against classify (#11-#15)` is a mention and closes
nothing, which is what it should do.

**Verify, do not assume.** `gh pr view <n> --json closingIssuesReferences` is
GitHub's own parse, not a guess from the body text. It also catches a keyword
whose link was broken by surrounding markdown — a code span or a list
continuation will do it. Bold will not, but check rather than trust that.

## Close-out

The parent closes when every attached slice is closed **and** the plan file is
stamped `Shipped (YYYY-MM-DD)` (or `Retired`) with a pointer to the landing
commit. That stamp is terminal; it cannot go stale. Do not keep a “terminator”
sibling issue — the parent *is* that signal.

## Skill

Agents file this shape via the project skill `file-plan-issues`. This file is
the protocol; the skill is the prompt that runs it. There is **one** launcher:

- [`.claude/skills/file-plan-issues/SKILL.md`](../.claude/skills/file-plan-issues/SKILL.md)

`SKILL.md` is the [Agent Skills](https://agentskills.io) open format, and clients
read each other's directories. Cursor loads `.agents/skills/` and `.cursor/skills/`
natively and, in its own words, *"for compatibility, Cursor also loads skills from
Claude and Codex directories: `.claude/skills/`, `.codex/skills/`, `~/.claude/skills/`,
and `~/.codex/skills/`"* ([docs](https://cursor.com/docs/context/skills)). So a
`.cursor/` copy buys nothing and costs a byte-identical duplicate that drifts the
first time someone edits one side.

`.claude/skills/` is the one path both read today: Claude Code scans only
`~/.claude/skills/` and `.claude/skills/` (plus parents to the repo root, plugin
and enterprise locations) — **not** the vendor-neutral `.agents/skills/`, which
Cursor does read. Moving there would silently drop the skill for Claude Code. If
that changes, `.agents/skills/` becomes the better home; re-introducing per-vendor
copies is the wrong answer either way.
