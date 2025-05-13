
use logos::Logos;
use smol_str::SmolStr;
use std::num::ParseIntError;
use std::fmt;

#[derive(Default, Debug, Clone, PartialEq)]
enum LexicalError {
    InvalidInteger(ParseIntError),
    #[default]
    InvalidToken,
}

impl fmt::Display for CedarToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action => write!(f, "action"),
            Self::Add => write!(f, "+"),
            Self::And => write!(f, "&&"),
            Self::At => write!(f, "@"),
            Self::Colon => write!(f, ":"),
            Self::Comma => write!(f, ","),
            // PANIC SAFETY: comment should be ignored as specified by the lexer regex
            #[allow(clippy::unreachable)]
            Self::Comment => unreachable!("comment should be skipped!"),
            Self::Context => write!(f, "context"),
            Self::Dash => write!(f, "-"),
            Self::Div => write!(f, "/"),
            Self::Dot => write!(f, "."),
            Self::DoubleColon => write!(f, "::"),
            Self::Else => write!(f, "else"),
            Self::Equal => write!(f, "=="),
            Self::False => write!(f, "false"),
            Self::Forbid => write!(f, "forbid"),
            Self::Ge => write!(f, ">="),
            Self::Gt => write!(f, ">"),
            Self::Has => write!(f, "has"),
            Self::Identifier(i) => write!(f, "{}", i),
            Self::If => write!(f, "if"),
            Self::In => write!(f, "in"),
            Self::LBrace => write!(f, "{{"),
            Self::LBracket => write!(f, "["),
            Self::LParen => write!(f, "("),
            Self::Le => write!(f, "<="),
            Self::Like => write!(f, "like"),
            Self::Is => write!(f, "is"),
            Self::Lt => write!(f, "<"),
            Self::Modulo => write!(f, "%"),
            Self::Mul => write!(f, "*"),
            Self::Neg => write!(f, "!"),
            Self::NotEqual => write!(f, "!="),
            Self::Number(n) => write!(f, "{}", n),
            Self::Or => write!(f, "||"),
            Self::Permit => write!(f, "permit"),
            Self::Principal => write!(f, "principal"),
            Self::PrincipalSlot => write!(f, "principal?"),
            Self::RBrace => write!(f, "}}"),
            Self::RBracket => write!(f, "]"),
            Self::RParen => write!(f, ")"),
            Self::Resource => write!(f, "resource"),
            Self::ResourceSlot => write!(f, "resource?"),
            Self::OtherSlot(_) => write!(f, "?slot"),
            Self::SemiColon => write!(f, ";"),
            Self::StringLit(s) => write!(f, "{}", s),
            Self::Then => write!(f, "then"),
            Self::True => write!(f, "true"),
            Self::Unless => write!(f, "unless"),
            Self::When => write!(f, "when"),
            Self::Assign => write!(f, "="),
            // PANIC SAFETY: whitespace should be ignored as specified by the lexer regex
            #[allow(clippy::unreachable)]
            Self::Whitespace => unreachable!("whitespace should be skipped!"),
        }
    }
}

// Cedar tokens
#[derive(Logos, Clone, Debug, PartialEq, Eq)]
pub enum CedarToken {
    #[regex(r"\s*", logos::skip)]
    Whitespace,

    #[regex(r"//[^\n\r]*[\n\r]*", logos::skip)]
    Comment,

    #[token("true")]
    True,

    #[token("false")]
    False,

    #[token("if")]
    If,

    #[token("permit")]
    Permit,

    #[token("forbid")]
    Forbid,

    #[token("when")]
    When,

    #[token("unless")]
    Unless,

    #[token("in")]
    In,

    #[token("has")]
    Has,

    #[token("like")]
    Like,

    #[token("is")]
    Is,

    #[token("then")]
    Then,

    #[token("else")]
    Else,

    #[token("principal")]
    Principal,

    #[token("action")]
    Action,

    #[token("resource")]
    Resource,

    #[token("context")]
    Context,

    #[token("?principal")]
    PrincipalSlot,

    #[token("?resource")]
    ResourceSlot,

    #[regex(r"\?[_a-zA-Z][_a-zA-Z0-9]*", |lex| SmolStr::new(lex.slice()))]
    OtherSlot(SmolStr),

    #[regex(r"[_a-zA-Z][_a-zA-Z0-9]*", |lex| SmolStr::new(lex.slice()))]
    Identifier(SmolStr),

    #[regex("[0-9]+", |lex| SmolStr::new(lex.slice()))]
    Number(SmolStr),

    #[regex(r#""(\\.|[^"\\])*""#, |lex| SmolStr::new(lex.slice()))]
    StringLit(SmolStr),

    #[token("@")]
    At,

    #[token(".")]
    Dot,

    #[token(",")]
    Comma,

    #[token(";")]
    SemiColon,

    #[token(":")]
    Colon,

    #[token("::")]
    DoubleColon,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token("{")]
    LBrace,

    #[token("}")]
    RBrace,

    #[token("[")]
    LBracket,

    #[token("]")]
    RBracket,

    #[token("==")]
    Equal,

    #[token("!=")]
    NotEqual,

    #[token("<")]
    Lt,

    #[token("<=")]
    Le,

    #[token(">")]
    Gt,

    #[token(">=")]
    Ge,

    #[token("||")]
    Or,

    #[token("&&")]
    And,

    #[token("+")]
    Add,

    #[token("-")]
    Dash,

    #[token("*")]
    Mul,

    #[token("/")]
    Div,

    #[token("%")]
    Modulo,

    #[token("!")]
    Neg,

    #[token("=")]
    Assign,
}
