# Template: create a User Story (bounded track/slice)

```json
{
  "project": {"id": "DL"},
  "summary": "<Track/slice name — e.g. \"Track A — UDP/TCP upstream backends\">",
  "description": "<Scope of this slice, its non-goals, and how it fits the parent Epic's objective.>",
  "customFields": [
    {"name": "Type", "$type": "SingleEnumIssueCustomField", "value": {"name": "User Story"}},
    {"name": "Stage", "$type": "StateIssueCustomField", "value": {"name": "Backlog"}},
    {"name": "Sprint DL", "$type": "SingleEnumIssueCustomField", "value": {"name": "<X.Y>"}}
  ],
  "links": [{"linkType": "Subtask", "direction": "INWARD", "issues": [{"id": "DL-<epic id>"}]}]
}
```

Set `Role` once the field's value bundle has entries (see
`rules/youtrack.md`'s note); until then omit it rather than let issue
creation fail on an unpopulated bundle value.

Break the Story into `Task` children covering the applicable model, engine,
server, upstream, fakeip, hooks, facade, test, CI, documentation, and
packaging work — see `task.md`. Every Task must roll up to a Story.
