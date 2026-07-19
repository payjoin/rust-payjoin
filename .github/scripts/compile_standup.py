#!/usr/bin/env python3
"""Update the latest Weekly Check-in Discussion body with participation summary."""

import os
import re
from pathlib import Path

import requests
import yaml

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["STANDUP_TOKEN"]
GRAPHQL = "https://api.github.com/graphql"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "standup-contributors.yml"


def load_contributors():
    """Return configured proactive check-in prompts, if any."""
    if not _CONFIG_PATH.exists():
        return []
    with open(_CONFIG_PATH) as f:
        data = yaml.safe_load(f) or {}
    return [c["username"] for c in data.get("contributors", [])]


CONTRIBUTORS = load_contributors()
BOT_LOGIN = "payjoin-bot"
SUCCESS_MARKER = "### Shipped"
TRIGGER_RE = re.compile(r"(?im)(^|\s)/check-in\b")


def graphql(query, variables=None):
    """Run a GraphQL query and return the data."""
    resp = requests.post(
        GRAPHQL,
        headers=HEADERS,
        json={"query": query, "variables": variables or {}},
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data["data"]


def find_latest_checkin():
    """Find the most recent Weekly Check-in Discussion."""
    owner, name = REPO.split("/")
    data = graphql(
        """
        query($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            discussions(first: 10, orderBy: {field: CREATED_AT, direction: DESC}) {
              nodes {
                id
                title
                url
                body
              }
            }
          }
        }
        """,
        {"owner": owner, "name": name},
    )
    for d in data["repository"]["discussions"]["nodes"]:
        if d["title"].startswith("Weekly Check-in:"):
            return d
    return None


def get_discussion_comments(discussion_id):
    """Fetch top-level comments and their replies for a Discussion."""
    data = graphql(
        """
        query($id: ID!) {
          node(id: $id) {
            ... on Discussion {
              comments(first: 50) {
                nodes {
                  body
                  author { login }
                  replies(first: 50) {
                    nodes {
                      body
                      author { login }
                    }
                  }
                }
              }
            }
          }
        }
        """,
        {"id": discussion_id},
    )
    return data["node"]["comments"]["nodes"]


def check_participation(comments):
    """Return list of contributors who participated in this check-in."""
    participated = []
    seen = set()
    for comment in comments:
        body = comment["body"]
        for user in CONTRIBUTORS:
            if f"@{user}" not in body:
                continue
            reply_authors = {
                r["author"]["login"] for r in comment["replies"]["nodes"] if r["author"]
            }
            if user in reply_authors and user not in seen:
                participated.append(user)
                seen.add(user)
        author = (comment.get("author") or {}).get("login")
        if not author or author in seen or not TRIGGER_RE.search(body):
            continue
        for reply in comment["replies"]["nodes"]:
            reply_author = (reply.get("author") or {}).get("login")
            reply_body = reply.get("body") or ""
            if reply_author == BOT_LOGIN and reply_body.startswith(SUCCESS_MARKER):
                participated.append(author)
                seen.add(author)
                break
    return participated


def update_discussion_body(discussion_id, new_body):
    """Edit the Discussion body via GraphQL."""
    graphql(
        """
        mutation($discussionId: ID!, $body: String!) {
          updateDiscussion(input: {
            discussionId: $discussionId,
            body: $body
          }) {
            discussion { id }
          }
        }
        """,
        {"discussionId": discussion_id, "body": new_body},
    )


PARTICIPATION_MARKER = "<!-- participation -->"


def main():
    dry_run = os.environ.get("DRY_RUN")

    discussion = find_latest_checkin()
    if not discussion:
        print("No Weekly Check-in discussion found.")
        return

    print(f"Found: {discussion['url']}")

    comments = get_discussion_comments(discussion["id"])
    participated = check_participation(comments)

    if participated:
        names = ", ".join(f"@{u}" for u in participated)
        participation_line = f"**Participated:** {names}"
    else:
        participation_line = "**Participated:** _(none yet)_"

    # Strip any previous participation section, then append
    body = discussion["body"]
    if PARTICIPATION_MARKER in body:
        body = body[: body.index(PARTICIPATION_MARKER)].rstrip()

    new_body = f"{body}\n\n{PARTICIPATION_MARKER}\n{participation_line}"

    if dry_run:
        print(f"Would update body to:\n---\n{new_body}\n---")
        return

    update_discussion_body(discussion["id"], new_body)
    print(f"Updated discussion: {participation_line}")


if __name__ == "__main__":
    main()
