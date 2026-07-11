"""Git-based policy versioning.

Every policy change is committed with metadata (author, reason, timestamp).
Provides: list versions, get policy at version, diff between versions, rollback.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pygit2

logger = logging.getLogger("tracepath.policies.versioning")

RULES_DIR = "rules"
POLICY_FILES = ["main.rego", "allowlist.rego", "budget.rego", "ratelimit.rego"]


@dataclass
class PolicyVersion:
    """A point-in-time snapshot of the policy rules."""
    commit_hash: str
    author: str
    message: str
    timestamp: str
    changed_files: list[str] = field(default_factory=list)


class PolicyVersioning:
    """Git-based policy version manager."""

    def __init__(self, repo_path: str | None = None) -> None:
        if repo_path is None:
            # Default: policies/ directory relative to this file
            repo_path = str(Path(__file__).resolve().parent.parent)

        self.repo_path = repo_path
        self._repo: pygit2.Repository | None = None

        # Initialize repo if needed
        try:
            self._repo = pygit2.Repository(repo_path)
        except pygit2.GitError:
            logger.info("No git repo at %s — initializing", repo_path)
            self._init_repo()

    # ── Public API ──

    def list_versions(self, limit: int = 50) -> list[PolicyVersion]:
        """List policy versions from newest to oldest."""
        repo = self._get_repo()
        versions = []
        try:
            head = repo.head.target
        except (pygit2.GitError, pygit2.InvalidSpecError):
            return versions

        for commit in repo.walk(head, pygit2.enums.SortMode.TIME):
            if len(versions) >= limit:
                break
            # Only include commits that touched policy files
            changed = self._changed_files(commit)
            if changed:
                versions.append(PolicyVersion(
                    commit_hash=str(commit.id)[:8],
                    author=commit.author.name,
                    message=commit.message.strip(),
                    timestamp=datetime.fromtimestamp(
                        commit.commit_time, tz=timezone.utc
                    ).isoformat(),
                    changed_files=changed,
                ))
        return versions

    def commit_policy(
        self, author: str, message: str, files: list[str] | None = None
    ) -> str | None:
        """Commit current policy state. Returns commit hash or None if no changes."""
        repo = self._get_repo()

        # Stage policy files
        rules_path = os.path.join(self.repo_path, RULES_DIR)
        index = repo.index

        target_files = files or POLICY_FILES
        changed = False
        for filename in target_files:
            filepath = os.path.join(rules_path, filename)
            if os.path.isfile(filepath):
                rel_path = f"{RULES_DIR}/{filename}"
                index.add(rel_path)
                changed = True

        if not changed:
            logger.debug("No policy changes to commit")
            return None

        index.write()

        # Create tree and commit
        tree = index.write_tree()
        sig = pygit2.Signature(author, f"{author}@tracepath.dev")
        commit_hash = repo.create_commit(
            "HEAD",
            sig,
            sig,
            message,
            tree,
            [repo.head.target] if not repo.head_is_unborn else [],
        )

        short_hash = str(commit_hash)[:8]
        logger.info("Policy committed: %s — %s", short_hash, message)
        return short_hash

    def get_policy_at(self, commit_hash: str, filename: str) -> str | None:
        """Get the content of a policy file at a specific commit."""
        repo = self._get_repo()
        try:
            commit = repo.revparse_single(commit_hash)
            tree = commit.tree
            entry = tree[f"{RULES_DIR}/{filename}"]
            blob = repo[entry.id]
            return blob.data.decode("utf-8")
        except (KeyError, ValueError, pygit2.GitError) as e:
            logger.warning("Failed to get policy %s at %s: %s", filename, commit_hash, e)
            return None

    def diff_versions(self, old_hash: str, new_hash: str) -> list[dict]:
        """Return a unified diff between two policy versions."""
        repo = self._get_repo()
        try:
            old_commit = repo.revparse_single(old_hash)
            new_commit = repo.revparse_single(new_hash)
        except (ValueError, KeyError, pygit2.GitError) as e:
            logger.warning("Diff failed: %s", e)
            return []

        old_tree = old_commit.tree
        new_tree = new_commit.tree

        diffs = []
        diff = repo.diff(old_tree, new_tree)
        for patch in diff:
            file_path = patch.delta.new_file.path
            hunks = []
            for hunk in patch.hunks:
                lines = []
                for line in hunk.lines:
                    # line.origin is a char: '+' (addition), '-' (deletion), ' ' (context)
                    prefix = line.origin if isinstance(line.origin, str) else chr(line.origin)
                    lines.append(f"{prefix}{line.content.strip()}")
                hunks.append({
                    "header": hunk.header.strip(),
                    "old_start": hunk.old_start,
                    "old_lines": hunk.old_lines,
                    "new_start": hunk.new_start,
                    "new_lines": hunk.new_lines,
                    "lines": lines,
                })
            diffs.append({
                "file": file_path,
                "old_file": patch.delta.old_file.path,
                "status": str(patch.delta.status),
                "hunks": hunks,
            })

        return diffs

    def rollback(self, commit_hash: str) -> bool:
        """Rollback policy files to a previous version."""
        repo = self._get_repo()
        for filename in POLICY_FILES:
            content = self.get_policy_at(commit_hash, filename)
            if content is None:
                logger.error("Rollback failed: cannot read %s at %s", filename, commit_hash)
                return False
            filepath = os.path.join(self.repo_path, RULES_DIR, filename)
            with open(filepath, "w") as f:
                f.write(content)

        # Commit the rollback
        self.commit_policy(
            author="tracepath",
            message=f"rollback: restored policies to {commit_hash}",
        )
        return True

    # ── Private ──

    def _get_repo(self) -> pygit2.Repository:
        if self._repo is None:
            self._repo = pygit2.Repository(self.repo_path)
        return self._repo

    def _init_repo(self) -> None:
        """Initialize a git repository for policy versioning."""
        self._repo = pygit2.init_repository(self.repo_path, initial_head="main")
        logger.info("Initialized policy git repo at %s", self.repo_path)

        # Initial commit with current rules
        rules_path = os.path.join(self.repo_path, RULES_DIR)
        index = self._repo.index
        if os.path.isdir(rules_path):
            for filename in POLICY_FILES:
                filepath = os.path.join(rules_path, filename)
                if os.path.isfile(filepath):
                    index.add(f"{RULES_DIR}/{filename}")

        index.write()
        tree = index.write_tree()
        sig = pygit2.Signature("tracepath", "tracepath@tracepath.dev")
        self._repo.create_commit(
            "HEAD",
            sig,
            sig,
            "Initial policy commit",
            tree,
            [],
        )
        logger.info("Initial policy commit created")

    @staticmethod
    def _changed_files(commit: pygit2.Commit) -> list[str]:
        """List policy files changed in this commit."""
        if not commit.parents:
            # Initial commit — all files are new
            return list(POLICY_FILES)

        parent = commit.parents[0]
        diff = parent.tree.diff_to_tree(commit.tree)
        changed = set()
        for patch in diff:
            path = patch.delta.new_file.path
            name = os.path.basename(path)
            if name in POLICY_FILES:
                changed.add(name)
        return sorted(changed)
