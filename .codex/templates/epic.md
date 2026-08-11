# Template: create a Stage Epic

`POST /api/issues?fields=idReadable` (project `DL`), once per roadmap stage:

```json
{
  "project": {"id": "DL"},
  "summary": "Stage <X.Y> — <one-line stage goal>",
  "description": "Roadmap/source: `index.md:<line>`, `ROADMAP.md:<line>`.\n\n## Objective\n\n<Externally observable outcome and explicit non-goals.>\n\n## Baseline audit\n\n- Current source contracts inspected.\n- Existing tests and CI jobs mapped.\n- Documentation and package metadata checked.\n- Platform and feature-gating assumptions recorded.\n\n## Decisions required\n\n- <Decision; link the ADR Article ID under DL-A-1 once accepted.>",
  "customFields": [
    {"name": "Type", "$type": "SingleEnumIssueCustomField", "value": {"name": "Epic"}},
    {"name": "Stage", "$type": "StateIssueCustomField", "value": {"name": "Backlog"}},
    {"name": "Sprint DL", "$type": "SingleEnumIssueCustomField", "value": {"name": "<X.Y>"}}
  ]
}
```

Then break the Epic into `User Story` children (one per bounded track/slice)
with a `parent` link to the new Epic's ID — see `story.md`.
