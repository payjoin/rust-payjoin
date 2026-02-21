#!/usr/bin/env python3
"""Create a weekly standup input issue and ping contributors."""

import os
from datetime import datetime, timezone

import requests

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["STANDUP_TOKEN"]
API = "https://api.github.com"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}

CONTRIBUTORS = [
    "DanGould",
    "spacebear21",
    "arminsabouri",
    "benalleng",
    "chavic",
    "zealsham",
    "Mshehu5",
]


def main():
    today = datetime.now(timezone.utc)
    week_label = today.strftime("%Y-%m-%d")
    title = f"Standup Input: Week of {week_label}"

    cc_line = " ".join(f"@{u}" for u in CONTRIBUTORS)
    body = (
        "Please reply by **Monday end-of-day** (your timezone).\n\n"
        "Format:\n"
        "- **Shipped**: What you landed last week (PR/issue links)\n"
        "- **Focus**: What you're working on this week\n"
        "- **Blockers**: Anything stopping you — name who can help\n\n"
        f"cc {cc_line}"
    )

    # Ensure the label exists
    label_url = f"{API}/repos/{REPO}/labels/standup-input"
    resp = requests.get(label_url, headers=HEADERS)
    if resp.status_code == 404:
        requests.post(
            f"{API}/repos/{REPO}/labels",
            headers=HEADERS,
            json={
                "name": "standup-input",
                "color": "0E8A16",
                "description": "Weekly standup input issue",
            },
        )

    # Create the issue
    resp = requests.post(
        f"{API}/repos/{REPO}/issues",
        headers=HEADERS,
        json={"title": title, "body": body, "labels": ["standup-input"]},
    )
    resp.raise_for_status()
    issue = resp.json()
    print(f"Created issue #{issue['number']}: {issue['html_url']}")


if __name__ == "__main__":
    main()
