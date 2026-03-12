"""Fetches new GitHub Actions CVEs from NVD and updates cve_db.json."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import date
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD = "github actions"


def fetch_nvd_cves(min_cvss: float, api_key: str | None) -> list[dict[str, object]]:
    """Query NVD API for GitHub Actions CVEs above a CVSS threshold."""
    params = f"?keywordSearch={KEYWORD.replace(' ', '+')}&cvssV3Severity=CRITICAL"
    url = NVD_API_URL + params

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"[update-cve-db] ERROR fetching NVD: {e}", file=sys.stderr)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})

        # Extract CVSS v3 base score
        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0]
            or metrics.get("cvssMetricV30", [{}])[0]
        )
        score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
        if float(score) < min_cvss:
            continue

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Only include if description mentions a specific action owner/repo pattern
        if "actions/" not in description.lower() and "github" not in description.lower():
            continue

        results.append(
            {
                "cve_id": cve_id,
                "description": description,
                "score": score,
            }
        )
    return results


def load_db(path: Path) -> list[dict[str, object]]:
    if path.exists():
        return json.loads(path.read_text())  # type: ignore[no-any-return]
    return []


def save_db(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(records, indent=2) + "\n")


_README_START = "<!-- cve-table-start -->"
_README_END = "<!-- cve-table-end -->"
_README_DATE_START = "<!-- cve-updated-start -->"
_README_DATE_END = "<!-- cve-updated-end -->"


def build_cve_table(records: list[dict[str, object]]) -> str:
    """Build a Markdown CVE table from confirmed (non-PENDING) DB entries."""
    confirmed = [r for r in records if r.get("action") != "PENDING_REVIEW"]
    rows = [
        "| CVE | Action | Description |",
        "|-----|--------|-------------|",
    ]
    for r in confirmed:
        cve_id = r["cve_id"]
        url = r.get("advisory_url", f"https://www.cve.org/CVERecord?id={cve_id}")
        action = r["action"]
        desc = str(r.get("description", "")).split("\n")[0]
        rows.append(f"| [{cve_id}]({url}) | `{action}` | {desc} |")
    return "\n".join(rows)


def update_readme_date(text: str) -> str:
    """Replace the last-updated date block with today's date."""
    start = text.find(_README_DATE_START)
    end = text.find(_README_DATE_END)
    if start == -1 or end == -1:
        return text
    today = date.today().isoformat()
    new_block = f"{_README_DATE_START}\n> [!NOTE]\n> Last updated: {today}\n{_README_DATE_END}"
    return text[:start] + new_block + text[end + len(_README_DATE_END):]


def update_readme(readme_path: Path, records: list[dict[str, object]]) -> bool:
    """Replace the CVE table section in README.md. Returns True if changed."""
    text = update_readme_date(readme_path.read_text())
    start = text.find(_README_START)
    end = text.find(_README_END)
    if start == -1 or end == -1:
        print(
            "[update-cve-db] WARNING: CVE table markers not found in README — skipping.",
            file=sys.stderr,
        )
        return False

    new_block = f"{_README_START}\n{build_cve_table(records)}\n{_README_END}"
    new_text = text[: start] + new_block + text[end + len(_README_END) :]
    if new_text == text:
        return False
    readme_path.write_text(new_text)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Update PipeGuard CVE database.")
    parser.add_argument("--db", required=True, help="Path to cve_db.json")
    parser.add_argument("--min-cvss", type=float, default=9.0)
    parser.add_argument("--readme", default="README.md", help="Path to README.md")
    args = parser.parse_args()

    db_path = Path(args.db)
    api_key = os.environ.get("NVD_API_KEY")

    existing = load_db(db_path)
    existing_ids = {str(r.get("cve_id", "")) for r in existing}

    new_cves = fetch_nvd_cves(args.min_cvss, api_key)
    added = 0
    for cve in new_cves:
        cve_id = str(cve["cve_id"])
        if cve_id in existing_ids:
            continue
        # New entry — action field must be filled manually or via follow-up enrichment.
        # We add it as a pending entry for human review.
        existing.append(
            {
                "action": "PENDING_REVIEW",
                "cve_id": cve_id,
                "description": cve["description"],
                "affected_refs": ["all_tags"],
                "advisory_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            }
        )
        existing_ids.add(cve_id)
        added += 1
        print(f"[update-cve-db] Added {cve_id}")

    save_db(db_path, existing)
    print(f"[update-cve-db] Done. {added} new CVE(s) added.")

    readme_path = Path(args.readme)
    if readme_path.exists():
        changed = update_readme(readme_path, existing)
        if changed:
            print("[update-cve-db] README.md CVE table updated.")
        else:
            print("[update-cve-db] README.md CVE table unchanged.")


if __name__ == "__main__":
    main()
