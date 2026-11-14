#!/usr/bin/env bash
# Prints code=false when a pull request changes documentation only, so ci.yml skips its Rust and
# Node jobs, and code=true otherwise. `pnpm verify plan` runs it too, so its answer and CI's agree. Whatever it cannot prove runs everything: a push, a git
# failure (git grep included), any other path, or a document under docs/ that code names (a test checks ADR 0015's
# tables against the capture index). A push to main always runs everything.
set -uo pipefail

docs_only() {
	[ "${EVENT:-}" = pull_request ] || return 1
	local list path
	# FILES, one path per line, replaces the diff: `pnpm verify plan` asks about uncommitted
	# changes and named paths with the same rules CI uses.
	if [ -n "${FILES+set}" ]; then
		list=$FILES
	else
		list=$(git diff --no-renames --name-only "$BASE...$HEAD") || return 1
	fi
	[ -n "$list" ] || return 1
	while IFS= read -r path; do
		case $path in
		README.md | AGENTS.md | CLAUDE.md | .changeset/*.md) ;;
		docs/*)
			# 0: code names the document; 1: nothing does; anything else: git grep failed.
			git grep -qF -e "$path" -- crates packages scripts fuzz ':!*.md'
			case $? in
			0)
				echo "$path is read by code" >&2
				return 1
				;;
			1) ;;
			*)
				echo "git grep failed for $path" >&2
				return 1
				;;
			esac
			;;
		*) return 1 ;;
		esac
	done <<<"$list"
}

if docs_only; then
	echo "Documentation only: the Rust and Node jobs are skipped." >&2
	echo code=false
else
	echo code=true
fi
