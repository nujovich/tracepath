"""CLI entrypoint for generating compliance reports.

Usage:
    python3 -m incident_service.report_cli finra [--period-start YYYY-MM-DD] [--period-end YYYY-MM-DD]
    python3 -m incident_service.report_cli eu-ai-act [--period-start YYYY-MM-DD] [--period-end YYYY-MM-DD]
"""

import argparse
import asyncio
import json
import os
import sys

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://tracepath:tracepath@localhost:5432/tracepath")


async def main():
    parser = argparse.ArgumentParser(description="Generate Tracepath compliance reports")
    parser.add_argument(
        "report_type", choices=["finra", "eu-ai-act"], help="Report type to generate"
    )
    parser.add_argument("--period-start", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--period-end", help="End date (YYYY-MM-DD)")
    parser.add_argument("--format", choices=["json", "html"], default="html", help="Output format")
    parser.add_argument("--output", help="Output file path (default: stdout)")
    args = parser.parse_args()

    # Lazy import to avoid requiring sqlalchemy for simple command invocation
    import asyncpg

    pool = await asyncpg.create_pool(DATABASE_URL)

    from .reports import ReportGenerator

    gen = ReportGenerator(pool)

    if args.report_type == "finra":
        report = await gen.generate_finra_report(args.period_start, args.period_end)
    else:
        report = await gen.generate_eu_ai_act_report(args.period_start, args.period_end)

    if args.format == "json":
        output = json.dumps(gen.to_dict(report), indent=2)
    else:
        output = gen.to_html(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
