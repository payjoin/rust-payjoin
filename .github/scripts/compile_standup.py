#!/usr/bin/env python3
"""Compile standup responses into a GitHub Discussion and close the issue."""

import os
from datetime import datetime, timezone, timedelta

import requests

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["STANDUP_TOKEN"]
CATEGORY_NODE_ID = os.environ["DISCUSSION_CATEGORY_NODE_ID"]
API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}


def find_standup_issue():
    """Find the most recent open standup-input issue from the last 7 days."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    resp = requests.get(
        f"{API}/repos/{REPO}/issues",
        headers=HEADERS,
        params={
            "labels": "standup-input",
            "state": "open",
            "since": since,
            "sort": "created",
            "direction": "desc",
            "per_page": 1,
        },
    )
    resp.raise_for_status()
    issues = resp.json()
    if not issues:
        print("No standup-input issue found in the last 7 days.")
        return None
    return issues[0]


def fetch_comments(issue_number):
    """Fetch all comments on an issue."""
    comments = []
    page = 1
    while True:
        resp = requests.get(
            f"{API}/repos/{REPO}/issues/{issue_number}/comments",
            headers=HEADERS,
            params={"per_page": 100, "page": page},
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        comments.extend(batch)
        page += 1
    return comments


def get_repo_node_id():
    """Get the repository node ID for the GraphQL mutation."""
    resp = requests.get(f"{API}/repos/{REPO}", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()["node_id"]


def create_discussion(title, body, repo_node_id):
    """Create a GitHub Discussion via GraphQL."""
    mutation = """
    mutation($repoId: ID!, $categoryId: ID!, $title: String!, $body: String!) {
      createDiscussion(input: {
        repositoryId: $repoId,
        categoryId: $categoryId,
        title: $title,
        body: $body
      }) {
        discussion {
          url
        }
      }
    }
    """
    resp = requests.post(
        GRAPHQL,
        headers=HEADERS,
        json={
            "query": mutation,
            "variables": {
                "repoId": repo_node_id,
                "categoryId": CATEGORY_NODE_ID,
                "title": title,
                "body": body,
            },
        },
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data["data"]["createDiscussion"]["discussion"]["url"]


def close_issue(issue_number, discussion_url):
    """Close the standup issue with a link to the compiled discussion."""
    requests.post(
        f"{API}/repos/{REPO}/issues/{issue_number}/comments",
        headers=HEADERS,
        json={"body": f"Compiled into discussion: {discussion_url}"},
    )
    requests.patch(
        f"{API}/repos/{REPO}/issues/{issue_number}",
        headers=HEADERS,
        json={"state": "closed"},
    )


def main():
    issue = find_standup_issue()
    if not issue:
        return

    issue_number = issue["number"]
    # Extract the week label from the issue title
    title_suffix = issue["title"].removeprefix("Standup Input: ")
    week_label = title_suffix or datetime.now(timezone.utc).strftime("Week of %Y-%m-%d")

    comments = fetch_comments(issue_number)

    # Build sections per contributor
    sections = []
    for comment in comments:
        user = comment["user"]["login"]
        if comment["user"]["type"] == "Bot":
            continue
        body = comment["body"].strip()
        sections.append(f"### @{user}\n{body}")

    updates = "\n\n".join(sections) if sections else "_No responses._"

    discussion_title = f"Weekly Check-in: {week_label}"
    discussion_body = updates

    repo_node_id = get_repo_node_id()
    discussion_url = create_discussion(discussion_title, discussion_body, repo_node_id)
    print(f"Created discussion: {discussion_url}")

    close_issue(issue_number, discussion_url)
    print(f"Closed issue #{issue_number}")


if __name__ == "__main__":
    main()
