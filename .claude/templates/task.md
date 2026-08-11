# Template: create a Task (one bounded unit of work)

```json
{
  "project": "DL",
  "summary": "<Imperative, bounded — e.g. \"Add UDP upstream backend implementing the upstream trait\">",
  "description": "<What must change: files, public API impact, platform/feature assumptions, tests, cleanup behavior, and what counts as completion evidence.>",
  "customFields": {
    "Type": "Task",
    "Stage": "Backlog",
    "Sprint DL": "<X.Y>"
  },
  "parentIssue": "DL-<story id>"
}
```

Set `Role` (researcher/architect/implementer/reviewer/primary) and
`Platform` (`Linux`/`Windows`/`Darwin`/`Cross-platform`) once their value
bundles are populated in the YouTrack project (see
`@.claude/rules/youtrack.md`); until then omit them rather than let issue
creation fail on an unpopulated bundle value. `Platform` should list only
the platforms the Task actually touches — most DNS Lattice Tasks are
`Cross-platform` per the crate's design goal.

## Recording progress

Post evidence as a comment on the Task via `mcp__youtrack__add_issue_comment`
(see `@.claude/rules/youtrack.md` for the required comment structure), and
advance `Stage` (`Backlog` → `Develop` → `Review` → `Test` → `Staging` →
`Done`) as work progresses. Do not set `Done` without an independent
reviewer comment confirming no unresolved defects.

## Filing a Bug found during implementation/review

```json
{
  "project": "DL",
  "summary": "<Concrete defect summary>",
  "description": "<Repro, expected vs actual, evidence.>",
  "customFields": {
    "Type": "Bug",
    "Stage": "Backlog",
    "Priority": "Major"
  }
}
```

Then `mcp__youtrack__link_issues` with `linkType: "relates to"` back to the
Task/Story it affects.
