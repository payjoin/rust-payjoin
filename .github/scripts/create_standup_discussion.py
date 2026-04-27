#!/usr/bin/env python3
"""Create a weekly standup Discussion with auto-gathered activity per contributor."""

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import yaml

from standup_lib import (
    API,
    HEADERS,
    REPO,
    format_contributor_comment,
    gather_activity,
    gather_potential_bottlenecks,
    graphql,
)

CATEGORY_NODE_ID = os.environ["DISCUSSION_CATEGORY_NODE_ID"]

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "standup-contributors.yml"
with open(_CONFIG_PATH) as _f:
    CONTRIBUTORS = [c["username"] for c in yaml.safe_load(_f)["contributors"]]


def get_repo_node_id():
    """Get the repository node ID for GraphQL mutations."""
    resp = requests.get(f"{API}/repos/{REPO}", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()["node_id"]


def create_discussion(title, body, repo_node_id):
    """Create a GitHub Discussion via GraphQL and return its node ID and URL."""
    data = graphql(
        """
        mutation($repoId: ID!, $categoryId: ID!, $title: String!, $body: String!) {
          createDiscussion(input: {
            repositoryId: $repoId,
            categoryId: $categoryId,
            title: $title,
            body: $body
          }) {
            discussion {
              id
              url
            }
          }
        }
        """,
        {
            "repoId": repo_node_id,
            "categoryId": CATEGORY_NODE_ID,
            "title": title,
            "body": body,
        },
    )
    discussion = data["createDiscussion"]["discussion"]
    return discussion["id"], discussion["url"]


def add_discussion_comment(discussion_id, body):
    """Add a threaded comment to a Discussion via GraphQL."""
    graphql(
        """
        mutation($discussionId: ID!, $body: String!) {
          addDiscussionComment(input: {
            discussionId: $discussionId,
            body: $body
          }) {
            comment {
              id
            }
          }
        }
        """,
        {"discussionId": discussion_id, "body": body},
    )


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
              }
            }
          }
        }
        """,
        {"owner": owner, "name": name},
    )
    for discussion in data["repository"]["discussions"]["nodes"]:
        if discussion["title"].startswith("Weekly Check-in:"):
            return discussion
    return None


def get_discussion_comments(discussion_id):
    """Fetch top-level comments for a Discussion."""
    data = graphql(
        """
        query($id: ID!) {
          node(id: $id) {
            ... on Discussion {
              comments(first: 50) {
                nodes {
                  body
                  url
                }
              }
            }
          }
        }
        """,
        {"id": discussion_id},
    )
    return data["node"]["comments"]["nodes"]


def get_previous_thread_links():
    """Map contributors to the previous check-in thread created for them."""
    discussion = find_latest_checkin()
    if not discussion:
        return {}

    links = {}
    for comment in get_discussion_comments(discussion["id"]):
        user = next((u for u in CONTRIBUTORS if f"@{u}" in comment["body"]), None)
        if user:
            links[user] = comment["url"]
    return links


def main():
    today = datetime.now(timezone.utc)
    week_label = today.strftime("Week of %Y-%m-%d")
    since_date = today - timedelta(days=7)
    previous_thread_links = get_previous_thread_links()

    dry_run = os.environ.get("DRY_RUN")

    # Gather all comments first
    comments = []
    for user in CONTRIBUTORS:
        merged_prs, reviewed_prs, issues_opened = gather_activity(user, since_date)
        bottlenecks = gather_potential_bottlenecks(user, since_date)
        comment_body = format_contributor_comment(
            user,
            merged_prs,
            reviewed_prs,
            issues_opened,
            bottlenecks,
            previous_thread_links.get(user),
        )
        comments.append((user, comment_body))

    if dry_run:
        for user, comment_body in comments:
            print(f"--- {user} ---\n{comment_body}\n")
        print("Dry run complete — nothing was created.")
        return

    repo_node_id = get_repo_node_id()
    title = f"Weekly Check-in: {week_label}"
    body = (
        "Weekly standup — each contributor has a thread below "
        "with auto-gathered activity.\n\n"
        "**Reply to your thread by end-of-day Monday (your timezone).** "
        "Copy the template below and fill it in:\n\n"
        "```markdown\n"
        "### Shipped\n"
        "<!-- Add anything the bot missed: design work, specs, "
        "conversations, off-GitHub contributions. Correct any mistakes. "
        "Skip if the bot covered everything. -->\n"
        "\n"
        "### Focus\n"
        "What are you working on this week?\n"
        "\n"
        "### Bottleneck\n"
        "What is the single biggest bottleneck in progress toward your "
        "greater goal?\n"
        "Name your goal. Name the constraint. Name who or what can "
        "unblock it.\n"
        "```"
    )
    discussion_id, discussion_url = create_discussion(title, body, repo_node_id)
    print(f"Created discussion: {discussion_url}")

    for user, comment_body in comments:
        add_discussion_comment(discussion_id, comment_body)
        print(f"  Added thread for @{user}")

    print("Done.")


if __name__ == "__main__":
    main()
