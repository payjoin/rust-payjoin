#!/usr/bin/env python3
"""Create a weekly standup Discussion with auto-gathered activity per contributor."""

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

CONTRIBUTORS = [
    "DanGould",
    "spacebear21",
    "arminsabouri",
    "benalleng",
    "chavic",
    "zealsham",
    "Mshehu5",
]

ORG = "payjoin"


def get_repo_node_id():
    """Get the repository node ID for GraphQL mutations."""
    resp = requests.get(f"{API}/repos/{REPO}", headers=HEADERS)
    resp.raise_for_status()
    return resp.json()["node_id"]


def create_discussion(title, body, repo_node_id):
    """Create a GitHub Discussion via GraphQL and return its node ID and URL."""
    mutation = """
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
    discussion = data["data"]["createDiscussion"]["discussion"]
    return discussion["id"], discussion["url"]


def add_discussion_comment(discussion_id, body):
    """Add a threaded comment to a Discussion via GraphQL."""
    mutation = """
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
    """
    resp = requests.post(
        GRAPHQL,
        headers=HEADERS,
        json={
            "query": mutation,
            "variables": {
                "discussionId": discussion_id,
                "body": body,
            },
        },
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")


def search_issues(query):
    """Run a GitHub search/issues query and return the items."""
    resp = requests.get(
        f"{API}/search/issues",
        headers=HEADERS,
        params={"q": query, "per_page": 30},
    )
    resp.raise_for_status()
    return resp.json().get("items", [])


def gather_activity(user, since_date):
    """Gather a contributor's past-week activity across the org."""
    since = since_date.strftime("%Y-%m-%d")

    # PRs merged (authored)
    merged_prs = search_issues(f"author:{user} org:{ORG} type:pr merged:>{since}")

    # PRs reviewed
    reviewed_prs = search_issues(
        f"reviewed-by:{user} org:{ORG} type:pr updated:>{since}"
    )
    # Exclude PRs the user authored (already counted above)
    reviewed_prs = [pr for pr in reviewed_prs if pr["user"]["login"] != user]

    # Issues opened
    issues_opened = search_issues(
        f"author:{user} org:{ORG} type:issue created:>{since}"
    )

    return merged_prs, reviewed_prs, issues_opened


def gather_potential_blockers(user, since_date):
    """Identify potential blockers for a contributor (stretch goal)."""
    since = since_date.strftime("%Y-%m-%d")
    blockers = []

    # Open PRs with no reviews
    open_prs = search_issues(
        f"author:{user} org:{ORG} type:pr state:open review:none created:>{since}"
    )
    for pr in open_prs:
        blockers.append(f"- PR awaiting review: [{pr['title']}]({pr['html_url']})")

    # PRs with requested changes
    changes_requested = search_issues(
        f"author:{user} org:{ORG} type:pr state:open review:changes_requested"
    )
    for pr in changes_requested:
        blockers.append(
            f"- PR has requested changes: [{pr['title']}]({pr['html_url']})"
        )

    return blockers


def format_contributor_comment(user, merged_prs, reviewed_prs, issues_opened, blockers):
    """Format the threaded reply for a contributor."""
    lines = [f"## @{user}", ""]

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
        lines.append("_No activity found — please edit to add yours._")

    # Focus section (for contributor to fill in)
    lines.append("")
    lines.append("### Focus")
    lines.append("_What are you working on this week? (please edit)_")

    # Blockers section
    lines.append("")
    lines.append("### Blockers")
    if blockers:
        lines.append("_Auto-detected (please edit/confirm):_")
        lines.extend(blockers)
    else:
        lines.append("_Any blockers? Name who can help. (please edit)_")

    return "\n".join(lines)


def main():
    today = datetime.now(timezone.utc)
    week_label = today.strftime("Week of %Y-%m-%d")
    since_date = today - timedelta(days=7)

    repo_node_id = get_repo_node_id()

    # Create the Discussion
    title = f"Weekly Check-in: {week_label}"
    body = (
        "Weekly standup — each contributor has a thread below "
        "with auto-gathered activity.\n\n"
        "**Please review your thread and edit to add Focus and Blockers "
        "by end-of-day Monday (your timezone).**"
    )
    discussion_id, discussion_url = create_discussion(title, body, repo_node_id)
    print(f"Created discussion: {discussion_url}")

    # Create a threaded reply for each contributor
    for user in CONTRIBUTORS:
        merged_prs, reviewed_prs, issues_opened = gather_activity(user, since_date)
        blockers = gather_potential_blockers(user, since_date)
        comment_body = format_contributor_comment(
            user, merged_prs, reviewed_prs, issues_opened, blockers
        )
        add_discussion_comment(discussion_id, comment_body)
        print(f"  Added thread for @{user}")

    print("Done.")


if __name__ == "__main__":
    main()
