# Template: create a User Story (bounded track/slice)

```json
{
  "project": "DL",
  "summary": "<Track/slice name — e.g. \"Track A — UDP/TCP upstream backends\">",
  "description": "<Scope of this slice, its non-goals, and how it fits the parent Epic's objective.>",
  "customFields": {
    "Type": "User Story",
    "Stage": "Backlog",
    "Sprint DL": "<X.Y>"
  },
  "parentIssue": "DL-<epic id>"
}
```

Set `Role` once the field's value bundle has entries (see
`@.claude/rules/youtrack.md`'s custom-fields note); until then omit it
rather than let issue creation fail on an unpopulated bundle value.

Break the Story into `Task` children covering the applicable model, engine,
server, upstream, fakeip, hooks, facade, test, CI, documentation, and
packaging work — see `task.md`. Every Task must roll up to a Story; do not
leave bare Tasks parented directly on an Epic except for genuinely small
stages.
