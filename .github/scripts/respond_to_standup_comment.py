#!/usr/bin/env python3
"""Respond to a `/check-in` comment in a Weekly Check-in Discussion.

Triggered by `.github/workflows/standup-on-comment.yml` on
`discussion_comment` events. The workflow's `if:` block already filters
to the Check-ins category and `Weekly Check-in:` titles; this script does
the precise regex match and the per-week cap.
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
    parse_github_datetime,
)

BOT_LOGIN = "payjoin-bot"
TRIGGER_RE = re.compile(r"(?im)(^|\s)/check-in\b")
SUCCESS_MARKER = "### Shipped"
ERROR_BODY = "_Bot couldn't gather activity right now. Try again in a few minutes._"


def has_prior_success(discussion_id, author):
    """Return True if payjoin-bot has already posted a successful summary
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
            if reply_author != BOT_LOGIN:
                continue
            if (reply.get("body") or "").startswith(SUCCESS_MARKER):
                return True
    return False


def post_reply(discussion_id, reply_to_id, body):
    """Post a threaded reply via GraphQL ``addDiscussionComment``."""
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

    if comment_author == BOT_LOGIN:
        print("Loop guard: comment author is the bot; exiting.")
        return

    if has_prior_success(discussion_id, comment_author):
        print(
            f"Per-week cap: {comment_author} already received a successful "
            "summary in this Discussion; exiting."
        )
        return

    since_date = parse_github_datetime(discussion_created_at) - timedelta(days=7)

    try:
        merged_prs, reviewed_prs, issues_opened = gather_activity(
            comment_author, since_date
        )
        bottlenecks = gather_potential_bottlenecks(comment_author, since_date)
        body = format_contributor_comment(
            comment_author,
            merged_prs,
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
