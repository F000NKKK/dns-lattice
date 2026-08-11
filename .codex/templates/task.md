# Template: create a Task (one bounded unit of work)

```json
{
  "project": {"id": "DL"},
  "summary": "<Imperative, bounded — e.g. \"Add UDP upstream backend implementing the upstream trait\">",
  "description": "<What must change: files, public API impact, platform/feature assumptions, tests, cleanup behavior, and what counts as completion evidence.>",
  "customFields": [
    {"name": "Type", "$type": "SingleEnumIssueCustomField", "value": {"name": "Task"}},
    {"name": "Stage", "$type": "StateIssueCustomField", "value": {"name": "Backlog"}},
    {"name": "Sprint DL", "$type": "SingleEnumIssueCustomField", "value": {"name": "<X.Y>"}}
  ],
  "links": [{"linkType": "Subtask", "direction": "INWARD", "issues": [{"id": "DL-<story id>"}]}]
}
```

Set `Role` and `Platform` once their value bundles are populated (see
`rules/youtrack.md`); until then omit them. `Platform` should list only the
platforms the Task actually touches — most DNS Lattice Tasks are
`Cross-platform` per the crate's design goal.

## Recording progress

Post evidence as a comment on the Task (see `rules/youtrack.md` for the
required comment structure), and advance `Stage` (`Backlog` → `Develop` →
`Review` → `Test` → `Staging` → `Done`) as work progresses. Do not set
`Done` without an independent reviewer comment confirming no unresolved
defects.

## Filing a Bug found during implementation/review

```json
{
  "project": {"id": "DL"},
  "summary": "<Concrete defect summary>",
  "description": "<Repro, expected vs actual, evidence.>",
  "customFields": [
    {"name": "Type", "$type": "SingleEnumIssueCustomField", "value": {"name": "Bug"}},
    {"name": "Stage", "$type": "StateIssueCustomField", "value": {"name": "Backlog"}},
    {"name": "Priority", "$type": "SingleEnumIssueCustomField", "value": {"name": "Major"}}
  ]
}
```

Then link it `relates to` the Task/Story it affects.
