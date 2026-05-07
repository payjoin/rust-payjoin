use std::fmt;
use std::str::FromStr;

use crate::db::v2::SessionId;

/// A side-prefixed reference to a v2 session, as accepted by the
/// `payjoin-cli fallback` subcommand.
///
/// Sender and receiver session ids are auto-incremented per table, so a
/// bare numeric id can collide between the two tables. The `s` / `r`
/// prefix tells the dispatcher which side the operator means without a
/// table-existence guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRef {
    Send(SessionId),
    Recv(SessionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRefParseError {
    Empty,
    MissingSide,
    UnknownSide(char),
    MissingNumber,
    InvalidNumber(String),
}

impl fmt::Display for SessionRefParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty =>
                write!(f, "session ref must not be empty (expected `s<n>` or `r<n>`, e.g. `s1`, `r2`)"),
            Self::MissingSide =>
                write!(f, "session ref must start with `s` (sender) or `r` (receiver), e.g. `s1`, `r2`"),
            Self::UnknownSide(c) => write!(
                f,
                "unknown session-ref prefix `{c}` (expected `s` for sender or `r` for receiver, e.g. `s1`, `r2`)"
            ),
            Self::MissingNumber =>
                write!(f, "session ref `{{s|r}}` must be followed by a non-negative integer, e.g. `s1`, `r2`"),
            Self::InvalidNumber(n) => write!(
                f,
                "invalid session number `{n}` (expected a non-negative integer, e.g. `s1`, `r2`)"
            ),
        }
    }
}

impl std::error::Error for SessionRefParseError {}

impl FromStr for SessionRef {
    type Err = SessionRefParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let prefix = chars.next().ok_or(SessionRefParseError::Empty)?;
        let rest = chars.as_str();
        match prefix {
            's' => parse_id(rest).map(SessionRef::Send),
            'r' => parse_id(rest).map(SessionRef::Recv),
            '0'..='9' => Err(SessionRefParseError::MissingSide),
            _ => Err(SessionRefParseError::UnknownSide(prefix)),
        }
    }
}

fn parse_id(rest: &str) -> Result<SessionId, SessionRefParseError> {
    if rest.is_empty() {
        return Err(SessionRefParseError::MissingNumber);
    }
    // Parse via u64 to reject negative numbers, leading whitespace, and
    // a leading `+` -- the auto-increment storage produces only
    // non-negative ids, so anything else is a typo.
    let id: u64 =
        rest.parse().map_err(|_| SessionRefParseError::InvalidNumber(rest.to_string()))?;
    let id: i64 =
        id.try_into().map_err(|_| SessionRefParseError::InvalidNumber(rest.to_string()))?;
    Ok(SessionId(id))
}

impl fmt::Display for SessionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionRef::Send(id) => write!(f, "s{id}"),
            SessionRef::Recv(id) => write!(f, "r{id}"),
        }
    }
}

/// clap-friendly wrapper around [`SessionRef::from_str`] that surfaces
/// the parse error as a `String` for the CLI value parser.
pub(crate) fn parse_session_ref(s: &str) -> Result<SessionRef, String> {
    s.parse::<SessionRef>().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_send_prefix() {
        assert_eq!(SessionRef::from_str("s1").unwrap(), SessionRef::Send(SessionId(1)));
        assert_eq!(SessionRef::from_str("s0").unwrap(), SessionRef::Send(SessionId(0)));
        assert_eq!(
            SessionRef::from_str("s9223372036854775807").unwrap(),
            SessionRef::Send(SessionId(i64::MAX))
        );
    }

    #[test]
    fn parses_recv_prefix() {
        assert_eq!(SessionRef::from_str("r42").unwrap(), SessionRef::Recv(SessionId(42)));
        assert_eq!(SessionRef::from_str("r0").unwrap(), SessionRef::Recv(SessionId(0)));
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(SessionRef::from_str(""), Err(SessionRefParseError::Empty));
    }

    #[test]
    fn rejects_bare_numeric() {
        assert_eq!(SessionRef::from_str("1"), Err(SessionRefParseError::MissingSide));
        assert_eq!(SessionRef::from_str("42"), Err(SessionRefParseError::MissingSide));
    }

    #[test]
    fn rejects_prefix_only() {
        assert_eq!(SessionRef::from_str("s"), Err(SessionRefParseError::MissingNumber));
        assert_eq!(SessionRef::from_str("r"), Err(SessionRefParseError::MissingNumber));
    }

    #[test]
    fn rejects_unknown_prefix() {
        assert_eq!(SessionRef::from_str("x1"), Err(SessionRefParseError::UnknownSide('x')));
        assert_eq!(SessionRef::from_str("S1"), Err(SessionRefParseError::UnknownSide('S')));
        assert_eq!(SessionRef::from_str("R1"), Err(SessionRefParseError::UnknownSide('R')));
    }

    #[test]
    fn rejects_negative_number() {
        assert_eq!(
            SessionRef::from_str("s-1"),
            Err(SessionRefParseError::InvalidNumber("-1".to_string()))
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert_eq!(
            SessionRef::from_str("s 1"),
            Err(SessionRefParseError::InvalidNumber(" 1".to_string()))
        );
    }

    #[test]
    fn rejects_overflow() {
        // i64::MAX + 1 expressed as a u64 fits in u64 but not i64.
        assert_eq!(
            SessionRef::from_str("s9223372036854775808"),
            Err(SessionRefParseError::InvalidNumber("9223372036854775808".to_string()))
        );
    }

    #[test]
    fn display_round_trips() {
        let send = SessionRef::Send(SessionId(7));
        assert_eq!(send.to_string(), "s7");
        assert_eq!(SessionRef::from_str(&send.to_string()).unwrap(), send);

        let recv = SessionRef::Recv(SessionId(99));
        assert_eq!(recv.to_string(), "r99");
        assert_eq!(SessionRef::from_str(&recv.to_string()).unwrap(), recv);
    }
}
