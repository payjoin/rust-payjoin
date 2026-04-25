"""Shared helpers for standup automation (weekly post + on-comment trigger)."""

import os
import time
from datetime import datetime

import requests

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["STANDUP_TOKEN"]
API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
}

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


SEARCH_QUERY = """
query($q: String!) {
  search(query: $q, type: ISSUE, first: 30) {
    nodes {
      ... on PullRequest {
        id
        title
        url
        number
        repository {
          nameWithOwner
        }
        author { login }
      }
      ... on Issue {
        id
        title
        url
        number
        repository {
          nameWithOwner
        }
        author { login }
      }
    }
  }
}
"""
# This avoids refetching review history for the same PR multiple times in one run.
PR_REVIEWS_CACHE = {}


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
                "number": node["number"],
                "repository": node["repository"]["nameWithOwner"],
                "user": {
                    "login": node["author"]["login"] if node.get("author") else ""
                },
            }
        )
    return items


def parse_github_datetime(value):
    """Parse a GitHub ISO 8601 timestamp into an aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def get_paginated(url, params=None):
    """GET a paginated REST collection and return all items."""
    items = []
    next_url = url
    next_params = params or {}
    while next_url:
        for attempt in range(5):
            resp = requests.get(
                next_url,
                headers=HEADERS,
                params=next_params,
                timeout=30,
            )
            if resp.status_code in {403, 429} or 500 <= resp.status_code < 600:
                wait = 2**attempt
                print(
                    f"REST request failed ({resp.status_code}), retrying in {wait}s..."
                )
                time.sleep(wait)
                continue
            resp.raise_for_status()
            break
        else:
            resp.raise_for_status()
        items.extend(resp.json())
        next_url = resp.links.get("next", {}).get("url")
        next_params = None
    return items


def get_pull_request_reviews(pr):
    """Return all submitted reviews for a pull request."""
    cache_key = (pr["repository"], pr["number"])
    if cache_key in PR_REVIEWS_CACHE:
        return PR_REVIEWS_CACHE[cache_key]

    reviews = get_paginated(
        f"{API}/repos/{pr['repository']}/pulls/{pr['number']}/reviews",
        {"per_page": 100},
    )
    PR_REVIEWS_CACHE[cache_key] = reviews
    return reviews


def latest_reviewed_at(pr, reviewer):
    """Return the reviewer's latest submitted review timestamp for a PR."""
    latest = None
    for review in get_pull_request_reviews(pr):
        if review.get("user", {}).get("login") != reviewer:
            continue
        submitted_at = review.get("submitted_at")
        if not submitted_at:
            continue
        submitted = parse_github_datetime(submitted_at)
        if latest is None or submitted > latest:
            latest = submitted
    return latest


def gather_activity(user, since_date):
    """Gather a contributor's past-week activity across the org."""
    since = since_date.strftime("%Y-%m-%d")

    # PRs merged (authored)
    merged_prs = search_issues(f"author:{user} type:pr merged:>{since}")

    # PRs reviewed use search  to find candidate PRs then confirm
    # the reviewer actually submitted a review during the standup window.
    review_candidates = search_issues(
        f"reviewed-by:{user} type:pr updated:>{since} sort:updated-desc"
    )
    seen_ids = set()
    reviewed_prs = []
    for pr in review_candidates:
        if pr["id"] in seen_ids or pr["user"]["login"] == user:
            continue
        reviewed_at = latest_reviewed_at(pr, user)
        if reviewed_at and reviewed_at > since_date:
            seen_ids.add(pr["id"])
            reviewed_prs.append(pr)

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
    user,
    merged_prs,
    reviewed_prs,
    issues_opened,
    bottlenecks,
    previous_thread_url=None,
    include_last_week=True,
):
    """Format the threaded reply for a contributor.

    With ``include_last_week=True`` (Monday's bulk post) the body opens with a
    user header + @-mention and ends with a "Last Week" link block. With
    ``include_last_week=False`` (on-demand /check-in reply) the body starts at
    ``### Shipped`` so the per-week-cap success marker matches, and there is no
    @-mention of the commenter.
    """
    lines = []
    if include_last_week:
        lines.extend([f"## {user}", "", f"@{user}", ""])

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

    if include_last_week:
        lines.append("")
        lines.append("### Last Week")
        if previous_thread_url:
            lines.append("")
            lines.append(
                f"Review your previous thread: [Last week's thread]({previous_thread_url})"
            )
        else:
            lines.append("_No previous thread found._")

    if bottlenecks:
        lines.append("")
        lines.append("_Auto-detected signals:_")
        lines.extend(bottlenecks)

    return "\n".join(lines)
