# sealantd Agent Guidelines

## Agent Defaults

- Every PR lands on the owner's roadmap page, `~/Developer/OSS/Sealant/roadmap-site/` (outside the
  repositories). When you open a PR in `mend`, `sealant` (Core) or `sealantd` — feature, fix, docs,
  CI or version bump — add `["<repo>", <number>]` to the `prs` of its feature in `roadmap.json`,
  under the version it ships in, then run `node build.mjs` there (it reads live PR states from
  GitHub and writes `index.html`).
- A PR that starts a feature the roadmap lacks adds the feature: a `name` and a one-line
  `description` of what it does and why. A decision only the owner can make goes in `decisions`
  with your `recommendation`; once it is made, remove it and record the outcome in the feature. When
  scope moves between releases, move the feature. If the roadmap directory is missing on your
  machine, say so in your report.
