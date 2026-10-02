#!/usr/bin/env python3
"""Respond to a `/check-in` comment in a Weekly Check-in Discussion.

Triggered by `.github/workflows/standup-on-comment.yml` on
`discussion_comment` events. The workflow's `if:` block already filters
to the Check-ins category and `Weekly Check-in:` titles; this script does
the precise regex match and the per-week cap.

Local dry run:

    DRY_RUN=1 \
      COMMENT_ID=dry-run \
      COMMENT_BODY=/check-in \
      COMMENT_AUTHOR="$(uv run --no-project python -c \
        'import sys; sys.stderr.write("GitHub username: "); print(input())')" \
      DISCUSSION_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      DISCUSSION_ID=dry-run \
      GITHUB_REPOSITORY=payjoin/rust-payjoin \
      BOT_LOGIN=payjoin-robot \
      STANDUP_TOKEN="$(uv run --no-project python -c \
        'from getpass import getpass; print(getpass("GitHub token: "))')" \
      uv run --with requests \
      python .github/scripts/respond_to_standup_comment.py
"""

import os
import re
import sys
from datetime import timedelta

from standup_lib import (
    format_contributor_comment,
    gather_activity,
    gather_potential_bottlenecks,
    graphql,
    is_bot_login,
    parse_github_datetime,
)

TRIGGER_RE = re.compile(r"(?im)(^|\s)/check-in\b")
SUCCESS_MARKER = "### Shipped"
ERROR_BODY = "_Bot couldn't gather activity right now. Try again in a few minutes._"
DRY_RUN = os.environ.get("DRY_RUN")


def has_prior_success(discussion_id, author):
    """Return True if the bot has already posted a successful summary
    in reply to a comment authored by ``author`` in this Discussion."""
    data = graphql(
        """
        query($id: ID!) {
          node(id: $id) {
            ... on Discussion {
              comments(first: 100) {
                nodes {
                  author { login }
                  replies(first: 100) {
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
    for top in data["node"]["comments"]["nodes"]:
        top_author = (top.get("author") or {}).get("login")
        if top_author != author:
            continue
        for reply in top["replies"]["nodes"]:
            reply_author = (reply.get("author") or {}).get("login")
            if not is_bot_login(reply_author):
                continue
            if (reply.get("body") or "").startswith(SUCCESS_MARKER):
                return True
    return False


def post_reply(discussion_id, reply_to_id, body):
    """Post a threaded reply via GraphQL ``addDiscussionComment``."""
    if DRY_RUN:
        print(body)
        return
    graphql(
        """
        mutation($discussionId: ID!, $replyToId: ID!, $body: String!) {
          addDiscussionComment(input: {
            discussionId: $discussionId,
            replyToId: $replyToId,
            body: $body
          }) {
            comment {
              id
            }
          }
        }
        """,
        {
            "discussionId": discussion_id,
            "replyToId": reply_to_id,
            "body": body,
        },
    )


def main():
    comment_id = os.environ["COMMENT_ID"]
    comment_body = os.environ["COMMENT_BODY"]
    comment_author = os.environ["COMMENT_AUTHOR"]
    discussion_id = os.environ["DISCUSSION_ID"]
    discussion_created_at = os.environ["DISCUSSION_CREATED_AT"]

    if not TRIGGER_RE.search(comment_body):
        print("No /check-in token matched; nothing to do.")
        return

    if is_bot_login(comment_author):
        print("Loop guard: comment author is the bot; exiting.")
        return

    if not DRY_RUN and has_prior_success(discussion_id, comment_author):
        print(
            f"Per-week cap: {comment_author} already received a successful "
            "summary in this Discussion; exiting."
        )
        return

    since_date = parse_github_datetime(discussion_created_at) - timedelta(days=7)

    try:
        merged_prs, opened_prs, reviewed_prs, issues_opened = gather_activity(
            comment_author, since_date
        )
        bottlenecks = gather_potential_bottlenecks(comment_author, since_date)
        body = format_contributor_comment(
            comment_author,
            merged_prs,
            opened_prs,
            reviewed_prs,
            issues_opened,
            bottlenecks,
            include_last_week=False,
        )
        post_reply(discussion_id, comment_id, body)
        print(f"Posted activity summary for @{comment_author}.")
    except Exception:
        try:
            post_reply(discussion_id, comment_id, ERROR_BODY)
        except Exception as post_err:
            print(f"Failed to post error reply: {post_err}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
