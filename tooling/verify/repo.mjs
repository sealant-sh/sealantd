// Git facts every verb ties its result to: the head, whether the tree is dirty, and what changed
// since the merge base.
import { execFileSync } from "node:child_process";

export const git = (root, ...args) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

const tryGit = (root, ...args) => {
  try {
    return git(root, ...args);
  } catch {
    return null;
  }
};

export const head = (root, base) => {
  const sha = git(root, "rev-parse", "HEAD");
  const branch = tryGit(root, "symbolic-ref", "--short", "-q", "HEAD") ?? "(detached)";
  const dirty = git(root, "status", "--porcelain", "--untracked-files=normal") !== "";
  const mergeBase = tryGit(root, "merge-base", base, "HEAD");
  return { sha, branch, dirty, base, mergeBase };
};

const lines = (text) => (text ? text.split("\n").filter(Boolean) : []);

// Every path the branch changes against `mergeBase`: commits, staged and unstaged edits, and new
// untracked files. Deleted and renamed paths count as changed.
export const changedFiles = (root, mergeBase) => {
  const files = new Set([
    ...lines(git(root, "diff", "--no-renames", "--name-only", mergeBase)),
    ...lines(git(root, "ls-files", "--others", "--exclude-standard")),
  ]);
  return [...files].sort();
};

// `**` crosses directories, `*` and `?` do not. Paths are repo-relative with `/`.
export const globToRegExp = (glob) => {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      const slash = glob[i + 2] === "/";
      re += slash ? "(?:.*/)?" : ".*";
      i += slash ? 2 : 1;
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
};

export const matchesAny = (file, globs) => globs.some((g) => globToRegExp(g).test(file));
