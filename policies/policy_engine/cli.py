"""CLI for policy versioning and replay.

Usage:
    python3 -m policy_engine.cli versions
    python3 -m policy_engine.cli diff <old_hash> <new_hash>
    python3 -m policy_engine.cli rollback <commit_hash>
    python3 -m policy_engine.cli replay <commit_hash> [--period-start YYYY-MM-DD] [--period-end YYYY-MM-DD]
"""

import argparse
import asyncio
import json
import os
import sys

from .versioning import PolicyVersioning
from .replay import ReplayEngine

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://tracepath:tracepath@localhost:5432/tracepath")


async def main():
    parser = argparse.ArgumentParser(description="Tracepath policy management")
    sub = parser.add_subparsers(dest="command")

    # versions
    sub.add_parser("versions", help="List policy versions")

    # diff
    diff_p = sub.add_parser("diff", help="Diff two policy versions")
    diff_p.add_argument("old_hash", help="Old commit hash")
    diff_p.add_argument("new_hash", help="New commit hash")

    # rollback
    rb_p = sub.add_parser("rollback", help="Rollback to a policy version")
    rb_p.add_argument("commit_hash", help="Commit hash to rollback to")

    # replay
    replay_p = sub.add_parser("replay", help="Replay historical events against a policy version")
    replay_p.add_argument("policy_version", help="Policy commit hash")
    replay_p.add_argument("--period-start", help="Start date (YYYY-MM-DD)")
    replay_p.add_argument("--period-end", help="End date (YYYY-MM-DD)")
    replay_p.add_argument("--limit", type=int, default=1000, help="Max events to replay")
    replay_p.add_argument("--output", choices=["json", "summary"], default="summary")

    args = parser.parse_args()

    if args.command == "versions":
        pv = PolicyVersioning()
        versions = pv.list_versions()
        for v in versions:
            print(f"{v.commit_hash}  {v.timestamp[:19]}  {v.author:15s}  {v.message}")
            if v.changed_files:
                print(f"  {'':>8}  {'':>19}  {'':>15}  changed: {', '.join(v.changed_files)}")

    elif args.command == "diff":
        pv = PolicyVersioning()
        diffs = pv.diff_versions(args.old_hash, args.new_hash)
        for d in diffs:
            print(f"--- {d['old_file']}")
            print(f"+++ {d['file']}")
            for hunk in d["hunks"]:
                print(hunk["header"])
                for line in hunk["lines"]:
                    print(line)

    elif args.command == "rollback":
        pv = PolicyVersioning()
        ok = pv.rollback(args.commit_hash)
        if ok:
            print(f"Rolled back to {args.commit_hash}")
        else:
            print("Rollback failed", file=sys.stderr)
            sys.exit(1)

    elif args.command == "replay":
        import asyncpg
        pool = await asyncpg.create_pool(DATABASE_URL)
        pv = PolicyVersioning()
        engine = ReplayEngine(versioning=pv, db_pool=pool)
        result = await engine.replay(
            policy_version=args.policy_version,
            period_start=args.period_start,
            period_end=args.period_end,
            limit=args.limit,
        )

        if args.output == "json":
            print(json.dumps(engine.to_summary(result), indent=2))
        else:
            print(f"Policy: {result.policy_version[:8]} — {result.policy_message}")
            print(f"Events replayed: {result.total_events}")
            print(f"Affected: {result.affected_events} ({result.newly_denied} newly denied, {result.newly_allowed} newly allowed)")
            print(f"Affected sessions: {result.affected_sessions}")
            if result.affected_events > 0:
                print("\nSample affected events:")
                for e in result.events:
                    if e.changed:
                        arrow = "➡ denied" if not e.replay_allowed else "➡ allowed"
                        print(f"  {e.event_id[:8]} | {e.session_id[:16]} | {e.tool_name:20s} | {arrow}")

        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())