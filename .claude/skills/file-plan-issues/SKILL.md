---
name: file-plan-issues
description: >-
  File a GitHub parent plan issue and one closeable sub-issue per plan slice.
  Use when the user asks to file plan issues, file slices, open a parent issue
  for a plan, or run the plan-workflow filing procedure. Also use after a
  docs/plans/*.md plan is authored and the user wants issues for it.
---

# File plan issues

Protocol: [docs/plan-workflow.md](../../../docs/plan-workflow.md). Read it before filing. Do not invent a board, a terminator sibling, or a checklist of slices on the parent.

## When

User says any of: file the plan, file slices, parent issue for the plan, `label:plan` / `label:slice`.

## Do this, in order

1. Confirm a remote (`gh repo view`). Create labels if missing:

   ```bash
   gh label create plan  --description "Parent plan issue for an arc" --color 0E8A16
   gh label create slice --description "Closeable slice of a plan parent" --color 1D76DB
   ```

2. Read the plan file. Its slice table columns are **Work** and **Done when**; those become the issue’s **Do** and **Close when**. If a slice cannot be closed as written, amend the plan first — do not file a mushy issue.

3. **Parent first.** `gh issue create --label plan --title "<arc title>" --body-file parent.md`. Always pass a body flag — a bare `create` opens an editor and hangs a non-interactive shell. Body: plan pointer, goal, out of scope, “close when every slice is closed”. No task list that restates children.

   **The plan pointer must be an absolute blob URL.** GitHub does *not* rewrite relative links in issue bodies. `[plan](docs/plans/x.md)` renders as a bare relative `href`, resolves against `…/issues/`, and 404s. Use `https://github.com/<owner>/<repo>/blob/main/docs/plans/<file>.md`.

4. Read the parent number. File each slice:

   ```bash
   gh issue create --parent <N> --label slice \
     --title "<N>-S<k>: <what the slice does>" \
     --body "..."
   ```

   Title prefix is the **parent number**, not a bare `S1`. Use `--parent`. Do not call GraphQL or REST `/sub_issues`.

5. Each slice body has four sections: Parent/plan pointer · Do · Close when (observable) · Not this slice. Name blockers **by issue number** — `Blocked on #<child>`, never `#<parent>-S<k>`: GitHub autolinks the `#<parent>` and leaves `-S<k>` as text, so every blocker silently points at the parent. A gate with no issue (missing corpus) is named in prose.

6. Attachment test: *when this arc closes, does that issue close too?* No → free-standing, link it, do not `--parent`.

7. Verify:

   ```bash
   gh issue view <N> --json title,labels,subIssues \
     -q '{title,labels:[.labels[].name],kids:[.subIssues.nodes[]|{number,title}]}'
   ```

   Parent label `plan` only. Children label `slice` only. Every child title starts with `<N>-S`.

8. Edit the parent once to replace placeholder slice names with `#` links. Navigation only: slice id, `#N`, one clause of what it is. Do **not** restate each child’s close condition — that is a third copy of a DoD that already lives in the plan file and in the child. Do **not** type a slice count; GitHub’s roll-up is the snapshot.

9. Return the parent URL and a table of slice URLs. Do not commit unless asked.

## Do not

- Put actionable work only in the parent body.
- File slices before the parent exists (no number to prefix).
- Close a gated slice (e.g. goldens with no corpus) as a TODO.
- Duplicate this protocol in the issue bodies; point at the plan file.
- Point the parent at the plan with a relative link.
- Write a blocker as `<parent>-S<k>` instead of the child’s `#` number.
- Narrow a plan statement while restating it in an issue. If the issue needs a tighter condition than the plan, fix the plan.
- Write a closer as a range or a comma list (`Closes #10-#15`, `Closes #10, #11`). GitHub links only the first `#N` after each keyword, so the range closes nothing and the list closes one. One keyword per issue, in the PR body; verify with `gh pr view <n> --json closingIssuesReferences`. Same rule in a commit message.
