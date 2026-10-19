//! Path patterns of declared inputs and `view.find`.
//!
//! Paths are `/`-separated and relative to a view. `**` matches any number
//! of directories (including none), `*` any run of characters inside one
//! name and `?` one character; letters match ASCII case-insensitively, as
//! on the Windows file systems the evidence often comes from.

/// Longest accepted pattern.
pub const MAX_PATTERN_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    /// `**`
    AnyDirectories,
    Name(Vec<Token>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token {
    Literal(char),
    AnyRun,
    AnyOne,
}

/// A compiled path pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Glob {
    pattern: String,
    segments: Vec<Segment>,
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Self, String> {
        let trimmed = pattern.trim().trim_start_matches('/');
        if trimmed.is_empty() || trimmed.len() > MAX_PATTERN_BYTES {
            return Err(format!(
                "pattern {pattern:?} must be 1..={MAX_PATTERN_BYTES} bytes"
            ));
        }
        let mut segments = Vec::new();
        for part in trimmed.split('/') {
            if part.is_empty() || part == "." || part == ".." || part.contains(['\\', '\0']) {
                return Err(format!(
                    "pattern {pattern:?} must not contain empty, '.', '..' or backslash segments"
                ));
            }
            if part == "**" {
                if segments.last() != Some(&Segment::AnyDirectories) {
                    segments.push(Segment::AnyDirectories);
                }
                continue;
            }
            if part.contains("**") {
                return Err(format!(
                    "pattern {pattern:?}: ** must be a whole path segment"
                ));
            }
            segments.push(Segment::Name(
                part.chars()
                    .map(|character| match character {
                        '*' => Token::AnyRun,
                        '?' => Token::AnyOne,
                        other => Token::Literal(other.to_ascii_lowercase()),
                    })
                    .collect(),
            ));
        }
        if segments.len() > 64 {
            return Err(format!("pattern {pattern:?} has more than 64 segments"));
        }
        if matches!(segments.last(), Some(Segment::AnyDirectories)) {
            return Err(format!(
                "pattern {pattern:?} must end with a file name pattern"
            ));
        }
        Ok(Self {
            pattern: trimmed.to_owned(),
            segments,
        })
    }

    /// A pattern for a file name anywhere in the view (`**/<name>`).
    pub fn anywhere(name: &str) -> Result<Self, String> {
        if name.contains('/') {
            return Err(format!("name pattern {name:?} must not contain '/'"));
        }
        Self::new(&format!("**/{name}"))
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Whether `path` (relative, `/`-separated) matches.
    pub fn matches(&self, path: &str) -> bool {
        let parts: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        match_segments(&self.segments, &parts)
    }

    /// Whether some path below `directory` could match, to prune walks.
    pub fn may_match_below(&self, directory: &str) -> bool {
        let parts: Vec<&str> = directory
            .trim_start_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        prefix_possible(&self.segments, &parts)
    }

    /// The leading segments without wildcards: where a walk can start.
    pub fn literal_prefix(&self) -> Vec<String> {
        let mut prefix = Vec::new();
        for segment in &self.segments {
            let Segment::Name(tokens) = segment else {
                break;
            };
            if tokens
                .iter()
                .any(|token| !matches!(token, Token::Literal(_)))
            {
                break;
            }
            prefix.push(
                tokens
                    .iter()
                    .map(|token| match token {
                        Token::Literal(character) => *character,
                        Token::AnyRun | Token::AnyOne => '*',
                    })
                    .collect(),
            );
        }
        // The last segment names files, not directories.
        if prefix.len() == self.segments.len() {
            prefix.pop();
        }
        prefix
    }

    /// Whether the pattern can match at any depth.
    pub fn is_recursive(&self) -> bool {
        self.segments.contains(&Segment::AnyDirectories)
    }
}

fn match_segments(segments: &[Segment], parts: &[&str]) -> bool {
    match segments.split_first() {
        None => parts.is_empty(),
        Some((Segment::AnyDirectories, rest)) => {
            (0..=parts.len()).any(|skip| match_segments(rest, &parts[skip..]))
        }
        Some((Segment::Name(tokens), rest)) => match parts.split_first() {
            Some((part, remaining)) => match_name(tokens, part) && match_segments(rest, remaining),
            None => false,
        },
    }
}

fn prefix_possible(segments: &[Segment], parts: &[&str]) -> bool {
    match (segments.split_first(), parts.split_first()) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some((Segment::AnyDirectories, _)), Some(_)) => true,
        (Some((Segment::Name(tokens), rest)), Some((part, remaining))) => {
            // The last segment matches files, never a directory to descend.
            !rest.is_empty() && match_name(tokens, part) && prefix_possible(rest, remaining)
        }
    }
}

fn match_name(tokens: &[Token], name: &str) -> bool {
    let characters: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (mut token, mut character) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while character < characters.len() {
        match tokens.get(token) {
            Some(Token::AnyRun) => {
                backtrack = Some((token, character));
                token += 1;
            }
            Some(Token::AnyOne) => {
                token += 1;
                character += 1;
            }
            Some(Token::Literal(literal)) if *literal == characters[character] => {
                token += 1;
                character += 1;
            }
            _ => match backtrack {
                Some((star, position)) => {
                    token = star + 1;
                    character = position + 1;
                    backtrack = Some((star, position + 1));
                }
                None => return false,
            },
        }
    }
    tokens[token..]
        .iter()
        .all(|token| matches!(token, Token::AnyRun))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_paths_case_insensitively() {
        let wtmp = Glob::new("var/log/wtmp*").expect("pattern");
        assert!(wtmp.matches("var/log/wtmp"));
        assert!(wtmp.matches("VAR/Log/wtmp.1"));
        assert!(!wtmp.matches("var/log/btmp"));
        assert!(!wtmp.matches("var/log/old/wtmp"));
        assert_eq!(wtmp.literal_prefix(), vec!["var", "log"]);
        assert!(!wtmp.is_recursive());

        let history = Glob::new("home/*/.bash_history").expect("pattern");
        assert!(history.matches("home/kali/.bash_history"));
        assert!(!history.matches("home/.bash_history"));
        assert!(history.may_match_below("home"));
        assert!(history.may_match_below("home/kali"));
        assert!(!history.may_match_below("etc"));

        let anywhere = Glob::anywhere("*_can.asc").expect("pattern");
        assert!(anywhere.matches("adas_can.asc"));
        assert!(anywhere.matches("data/log/canbus/adas_can.asc"));
        assert!(anywhere.may_match_below("any/where"));
        assert!(Glob::new("a?c").expect("pattern").matches("abc"));
        assert!(!Glob::new("a?c").expect("pattern").matches("ac"));
    }

    #[test]
    fn unsafe_patterns_are_rejected() {
        for pattern in ["", "../etc", "a//b", "a\\b", "**", "a/**b", "a/**"] {
            assert!(Glob::new(pattern).is_err(), "{pattern}");
        }
        assert!(Glob::anywhere("a/b").is_err());
    }
}
