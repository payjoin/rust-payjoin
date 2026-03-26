#!/usr/bin/env python3
"""Create a weekly standup Discussion with auto-gathered activity per contributor."""

import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import yaml

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["STANDUP_TOKEN"]
CATEGORY_NODE_ID = os.environ["DISCUSSION_CATEGORY_NODE_ID"]
API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "standup-contributors.yml"
with open(_CONFIG_PATH) as _f:
    CONTRIBUTORS = [c["username"] for c in yaml.safe_load(_f)["contributors"]]

# Public repos to search — explicit list avoids leaking private repo
# data when the bot token has org membership.
REPOS = [
    "payjoin/rust-payjoin",
    "payjoin/payjoin.org",
    "payjoin/payjoindevkit.org",
    "payjoin/cja",
    "payjoin/cja-2",
    "payjoin/bitcoin-hpke",
    "payjoin/ohttp",
    "payjoin/bitcoin_uri",
    "payjoin/bitcoin-uri-ffi",
    "payjoin/research-docs",
    "payjoin/multiparty-protocol-docs",
    "payjoin/btsim",
    "payjoin/tx-indexer",
    "Uniffi-Dart/uniffi-dart",
]

REPO_FILTER = " ".join(f"repo:{r}" for r in REPOS)


def graphql(query, variables=None):
    """Run a GraphQL query with retry on 403 rate limits."""
    for attempt in range(5):
        resp = requests.post(
            GRAPHQL,
            headers=HEADERS,
            json={"query": query, "variables": variables or {}},
        )
        if resp.status_code == 403:
            wait = 2**attempt
            print(f"Rate limited (403), retrying in {wait}s...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data["data"]
    resp.raise_for_status()


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


SEARCH_QUERY = """
query($q: String!) {
  search(query: $q, type: ISSUE, first: 30) {
    nodes {
      ... on PullRequest {
        id
        title
        url
        author { login }
      }
      ... on Issue {
        id
        title
        url
        author { login }
      }
    }
  }
}
"""


def search_issues(query):
    """Run a GitHub search query across REPOS using GraphQL."""
    q = f"{query} {REPO_FILTER}"
    data = graphql(SEARCH_QUERY, {"q": q})
    items = []
    for node in data["search"]["nodes"]:
        if not node:
            continue
        items.append(
            {
                "id": node["id"],
                "title": node["title"],
                "html_url": node["url"],
                "user": {
                    "login": node["author"]["login"] if node.get("author") else ""
                },
            }
        )
    return items


def gather_activity(user, since_date):
    """Gather a contributor's past-week activity across the org."""
    since = since_date.strftime("%Y-%m-%d")

    # PRs merged (authored)
    merged_prs = search_issues(f"author:{user} type:pr merged:>{since}")

    # PRs reviewed
    reviewed_prs = search_issues(f"reviewed-by:{user} type:pr updated:>{since}")
    # Exclude PRs the user authored (already counted above)
    reviewed_prs = [pr for pr in reviewed_prs if pr["user"]["login"] != user]

    # Issues opened
    issues_opened = search_issues(f"author:{user} type:issue created:>{since}")

    return merged_prs, reviewed_prs, issues_opened


def gather_potential_bottlenecks(user, since_date):
    """Identify potential bottlenecks for a contributor."""
    since = since_date.strftime("%Y-%m-%d")
    bottlenecks = []

    # Open PRs with no reviews
    open_prs = search_issues(
        f"author:{user} type:pr state:open review:none created:>{since}"
    )
    for pr in open_prs:
        bottlenecks.append(f"- PR awaiting review: [{pr['title']}]({pr['html_url']})")

    # PRs with requested changes
    changes_requested = search_issues(
        f"author:{user} type:pr state:open review:changes_requested"
    )
    for pr in changes_requested:
        bottlenecks.append(
            f"- PR has requested changes: [{pr['title']}]({pr['html_url']})"
        )

    return bottlenecks


def format_contributor_comment(
    user, merged_prs, reviewed_prs, issues_opened, bottlenecks
):
    """Format the threaded reply for a contributor."""
    lines = [f"## {user}", "", f"@{user}", ""]

    # SHIPPED section
    lines.append("### Shipped")
    if merged_prs or reviewed_prs or issues_opened:
        if merged_prs:
            lines.append("")
            lines.append("**PRs merged:**")
            for pr in merged_prs:
                lines.append(f"- [{pr['title']}]({pr['html_url']})")

        if reviewed_prs:
            lines.append("")
            lines.append("**PRs reviewed:**")
            for pr in reviewed_prs:
                lines.append(f"- [{pr['title']}]({pr['html_url']})")

        if issues_opened:
            lines.append("")
            lines.append("**Issues opened:**")
            for issue in issues_opened:
                lines.append(f"- [{issue['title']}]({issue['html_url']})")
    else:
        lines.append("_No activity found._")

    if bottlenecks:
        lines.append("")
        lines.append("_Auto-detected signals:_")
        lines.extend(bottlenecks)

    return "\n".join(lines)


def main():
    today = datetime.now(timezone.utc)
    week_label = today.strftime("Week of %Y-%m-%d")
    since_date = today - timedelta(days=7)

    dry_run = os.environ.get("DRY_RUN")

    # Gather all comments first
    comments = []
    for user in CONTRIBUTORS:
        merged_prs, reviewed_prs, issues_opened = gather_activity(user, since_date)
        bottlenecks = gather_potential_bottlenecks(user, since_date)
        comment_body = format_contributor_comment(
            user, merged_prs, reviewed_prs, issues_opened, bottlenecks
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
