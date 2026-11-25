//! ASN.1 lexer for the NGAP dialect (X.680 lexical rules, restricted to what TS 38.413 uses).

use core::fmt;

/// A lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// Type/value/module reference or keyword: `[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*`.
    Ident(String),
    /// Decimal number, with an optional leading `-`.
    Number(i128),
    /// `&name`: a class field reference (the name excludes the `&`).
    Amp(String),
    /// `::=`
    Assign,
    /// `...`
    Ellipsis,
    /// `..`
    DotDot,
    /// `.`
    Dot,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Pipe,
    Colon,
    Semi,
    /// `@`
    At,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Ident(s) => write!(f, "`{s}`"),
            Tok::Number(n) => write!(f, "`{n}`"),
            Tok::Amp(s) => write!(f, "`&{s}`"),
            Tok::Assign => f.write_str("`::=`"),
            Tok::Ellipsis => f.write_str("`...`"),
            Tok::DotDot => f.write_str("`..`"),
            Tok::Dot => f.write_str("`.`"),
            Tok::LBrace => f.write_str("`{`"),
            Tok::RBrace => f.write_str("`}`"),
            Tok::LParen => f.write_str("`(`"),
            Tok::RParen => f.write_str("`)`"),
            Tok::LBracket => f.write_str("`[`"),
            Tok::RBracket => f.write_str("`]`"),
            Tok::Comma => f.write_str("`,`"),
            Tok::Pipe => f.write_str("`|`"),
            Tok::Colon => f.write_str("`:`"),
            Tok::Semi => f.write_str("`;`"),
            Tok::At => f.write_str("`@`"),
        }
    }
}

/// A token with its 1-based source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
    pub col: u32,
}

/// A lexical error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub line: u32,
    pub col: u32,
    pub message: String,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for LexError {}

/// Tokenise `src`. Comments (`--` up to the next `--` or the end of the line) are dropped.
pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut line, mut line_start) = (0usize, 1u32, 0usize);

    macro_rules! push {
        ($tok:expr, $start:expr) => {
            out.push(Token {
                tok: $tok,
                line,
                col: ($start - line_start) as u32 + 1,
            })
        };
    }

    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                i += 1;
                line += 1;
                line_start = i;
            }
            b' ' | b'\t' | b'\r' | 0x0C => i += 1,
            b'-' if b.get(i + 1) == Some(&b'-') => {
                // comment: to the next `--` or the end of the line (bytes >= 0x80 never equal ASCII, so UTF-8 is safe)
                i += 2;
                while i < b.len() && b[i] != b'\n' {
                    if b[i] == b'-' && b.get(i + 1) == Some(&b'-') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b':' if b[i..].starts_with(b"::=") => {
                push!(Tok::Assign, i);
                i += 3;
            }
            b'.' => {
                let n = b[i..].iter().take_while(|&&x| x == b'.').count();
                let (tok, len) = match n {
                    1 => (Tok::Dot, 1),
                    2 => (Tok::DotDot, 2),
                    3 => (Tok::Ellipsis, 3),
                    _ => return Err(err(line, i - line_start, "unexpected run of `.`")),
                };
                push!(tok, i);
                i += len;
            }
            b'{' => {
                push!(Tok::LBrace, i);
                i += 1;
            }
            b'}' => {
                push!(Tok::RBrace, i);
                i += 1;
            }
            b'(' => {
                push!(Tok::LParen, i);
                i += 1;
            }
            b')' => {
                push!(Tok::RParen, i);
                i += 1;
            }
            b'[' => {
                push!(Tok::LBracket, i);
                i += 1;
            }
            b']' => {
                push!(Tok::RBracket, i);
                i += 1;
            }
            b',' => {
                push!(Tok::Comma, i);
                i += 1;
            }
            b'|' => {
                push!(Tok::Pipe, i);
                i += 1;
            }
            b':' => {
                push!(Tok::Colon, i);
                i += 1;
            }
            b';' => {
                push!(Tok::Semi, i);
                i += 1;
            }
            b'@' => {
                push!(Tok::At, i);
                i += 1;
            }
            b'&' if b.get(i + 1).is_some_and(u8::is_ascii_alphabetic) => {
                let start = i;
                i += 1;
                let end = ident_end(b, i);
                push!(Tok::Amp(src[i..end].to_owned()), start);
                i = end;
            }
            b'-' | b'0'..=b'9'
                if c.is_ascii_digit() || b.get(i + 1).is_some_and(u8::is_ascii_digit) =>
            {
                let start = i;
                if c == b'-' {
                    i += 1;
                }
                let digits = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let n: i128 = src[digits..i].parse().map_err(|_| {
                    err(line, start - line_start, "number does not fit in 128 bits")
                })?;
                push!(Tok::Number(if c == b'-' { -n } else { n }), start);
            }
            _ if c.is_ascii_alphabetic() => {
                let end = ident_end(b, i);
                push!(Tok::Ident(src[i..end].to_owned()), i);
                i = end;
            }
            _ => {
                let ch = src[i..].chars().next().unwrap_or('?');
                return Err(err(
                    line,
                    i - line_start,
                    format!("unexpected character {ch:?}"),
                ));
            }
        }
    }
    Ok(out)
}

/// End of the identifier starting at `i`: alphanumerics with single hyphens between them (never `--`).
fn ident_end(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        if b[i].is_ascii_alphanumeric()
            || (b[i] == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_alphanumeric))
        {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn err(line: u32, col0: usize, message: impl Into<String>) -> LexError {
    LexError {
        line,
        col: col0 as u32 + 1,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    fn id(s: &str) -> Tok {
        Tok::Ident(s.into())
    }

    #[test]
    fn identifiers_keep_inner_hyphens() {
        assert_eq!(
            toks("id-AMF-UE-NGAP-ID S-NSSAI a1-b2"),
            vec![id("id-AMF-UE-NGAP-ID"), id("S-NSSAI"), id("a1-b2")]
        );
    }

    #[test]
    fn comments_run_to_eol_or_next_double_hyphen() {
        assert_eq!(toks("a -- comment\nb"), vec![id("a"), id("b")]);
        assert_eq!(toks("a -- inline -- b\nc"), vec![id("a"), id("b"), id("c")]);
        assert_eq!(toks("-- **********\n-- x\n"), vec![]);
        assert_eq!(toks("Foo--glued comment\nBar"), vec![id("Foo"), id("Bar")]);
        assert_eq!(
            toks("a -- caf\u{e9} \u{201c}x\u{201d}\nb"),
            vec![id("a"), id("b")]
        );
    }

    #[test]
    fn punctuation_and_ranges() {
        assert_eq!(
            toks("(1..30|40, ...) ::= {&id}"),
            vec![
                Tok::LParen,
                Tok::Number(1),
                Tok::DotDot,
                Tok::Number(30),
                Tok::Pipe,
                Tok::Number(40),
                Tok::Comma,
                Tok::Ellipsis,
                Tok::RParen,
                Tok::Assign,
                Tok::LBrace,
                Tok::Amp("id".into()),
                Tok::RBrace
            ]
        );
        assert_eq!(
            toks("A.&b ({S}{@x})"),
            vec![
                id("A"),
                Tok::Dot,
                Tok::Amp("b".into()),
                Tok::LParen,
                Tok::LBrace,
                id("S"),
                Tok::RBrace,
                Tok::LBrace,
                Tok::At,
                id("x"),
                Tok::RBrace,
                Tok::RParen
            ]
        );
        assert_eq!(
            toks("a : b ; [ ]"),
            vec![
                id("a"),
                Tok::Colon,
                id("b"),
                Tok::Semi,
                Tok::LBracket,
                Tok::RBracket
            ]
        );
    }

    #[test]
    fn numbers() {
        assert_eq!(
            toks("0 65535 18446744073709551615"),
            vec![
                Tok::Number(0),
                Tok::Number(65535),
                Tok::Number(18446744073709551615)
            ]
        );
        assert_eq!(
            toks("-127..127"),
            vec![Tok::Number(-127), Tok::DotDot, Tok::Number(127)]
        );
        assert_eq!(
            toks("(-420..10000"),
            vec![
                Tok::LParen,
                Tok::Number(-420),
                Tok::DotDot,
                Tok::Number(10000)
            ]
        );
        assert!(lex("340282366920938463463374607431768211456").is_err());
    }

    #[test]
    fn positions_are_one_based() {
        let t = lex("a\n  bc").unwrap();
        assert_eq!((t[0].line, t[0].col, t[1].line, t[1].col), (1, 1, 2, 3));
    }

    #[test]
    fn unexpected_characters_are_errors_with_position() {
        let e = lex("a\n b \"x\"").unwrap_err();
        assert_eq!((e.line, e.col), (2, 4));
        assert!(lex("a \u{a0} b").is_err());
        assert!(lex("....").is_err());
    }
}
