#!/usr/bin/env bash
# Prints code=false when a pull request changes documentation only, so ci.yml skips its Rust and
# Node jobs, and code=true otherwise. Whatever it cannot prove runs everything: a push, a git
# failure, any other path, or a document under docs/ that code names (a test checks ADR 0015's
# tables against the capture index). A push to main always runs everything.
set -uo pipefail

docs_only() {
	[ "${EVENT:-}" = pull_request ] || return 1
	local list path
	list=$(git diff --no-renames --name-only "$BASE...$HEAD") || return 1
	[ -n "$list" ] || return 1
	while IFS= read -r path; do
		case $path in
		README.md | AGENTS.md | CLAUDE.md | .changeset/*.md) ;;
		docs/*)
			if git grep -qF -e "$path" -- crates packages scripts fuzz ':!*.md'; then
				echo "$path is read by code" >&2
				return 1
			fi
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
