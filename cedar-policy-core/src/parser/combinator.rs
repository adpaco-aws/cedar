use crate::parser::cst::*;
use nom::{
    branch::alt, bytes::complete::{tag, take_while1}, character::complete::{alpha1, alphanumeric1, char, multispace0, one_of}, combinator::{all_consuming, map, map_res, opt, recognize}, error::ParseError, multi::{many0, many1, separated_list0}, sequence::{delimited, pair, preceded, terminated, tuple}, IResult, Parser
};
use smol_str::SmolStr;
use std::sync::Arc;

use super::cst;

type Node<T> = super::node::Node<Option<T>>;

struct ParserState<'a> {
    src: &'a Arc<str>,
    keep_src: bool,
}

type ParseResult<'a, T> = IResult<&'a str, Node<T>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies(pub Vec<Node<Policy>>);

pub fn ws<'a, O, E: ParseError<&'a str>, F>(
    inner: F,
) -> impl Parser<&'a str, Output = O, Error = E>
where
    F: Parser<&'a str, Output = O, Error = E>,
{
    delimited(multispace0, inner, multispace0)
}

// Basic identifier parser
fn parse_ident(input: &str) -> IResult<&str, Node<Ident>> {
    let mut parser = recognize(pair(
        alt((alpha1, tag("_"))),
        many0(alt((alphanumeric1, tag("_")))),
    ));
    
    let (input, id) = parser.parse(input)?;

    let ident = match id {
        "principal" => Ident::Principal,
        "action" => Ident::Action,
        "resource" => Ident::Resource,
        "context" => Ident::Context,
        "true" => Ident::True,
        "false" => Ident::False,
        "permit" => Ident::Permit,
        "forbid" => Ident::Forbid,
        "when" => Ident::When,
        "unless" => Ident::Unless,
        "in" => Ident::In,
        "has" => Ident::Has,
        "like" => Ident::Like,
        "is" => Ident::Is,
        "if" => Ident::If,
        "then" => Ident::Then,
        "else" => Ident::Else,
        _ => Ident::Ident(SmolStr::new(id)),
    };

    Ok((input, Node::with_maybe_source_loc(Some(ident), None)))
}

fn parse_str(input: &str) -> IResult<&str, Node<Str>> {
    let mut parser = delimited(
        char('"'),
        take_while1(|c| c != '"'),
        char('"'),
    );
    
    let (input, content) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(
        Some(Str::String(SmolStr::new(content))),
        None
    )))
}

fn parse_annotation(input: &str) -> IResult<&str, Node<Annotation>> {
    let mut at_parser = char('@');
    let (input, _) = at_parser.parse(input)?;
    
    let (input, key) = parse_ident(input)?;
    
    let mut value_parser = opt(delimited(
        ws(char('(')),
        parse_str,
        ws(char(')')),
    ));
    let (input, value) = value_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Annotation { key, value }),
        None
    )))
}

fn parse_policy(input: &str) -> IResult<&str, Node<Policy>> {
    let mut parser = alt((
        map(
            tuple((
                many0(parse_annotation),
                parse_ident,
                delimited(
                    ws(char('(')),
                    separated_list0(ws(char(',')), parse_variable_def),
                    ws(char(')')),
                ),
                many0(parse_cond),
                ws(char(';')),
            )),
            |(annotations, effect, variables, conds, _)| {
                Policy::Policy(PolicyImpl {
                    annotations,
                    effect,
                    variables,
                    conds,
                })
            },
        ),
        #[cfg(feature = "tolerant-ast")]
        map(
            tuple((take_until(";"), char(';'))),
            |_| Policy::PolicyError,
        ),
    ));

    let (input, policy) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(policy), None)))
}

fn parse_expr(input: &str) -> IResult<&str, Node<Expr>> {
    let mut parser = alt((
        map(
            tuple((
                ws(tag("if")),
                parse_expr,
                ws(tag("then")),
                parse_expr,
                ws(tag("else")),
                parse_expr,
            )),
            |(_, cond, _, then_expr, _, else_expr)| {
                Expr::Expr(ExprImpl {
                    expr: Box::new(ExprData::If(cond, then_expr, else_expr)),
                })
            },
        ),
        map(parse_or, |or| {
            Expr::Expr(ExprImpl {
                expr: Box::new(ExprData::Or(or)),
            })
        }),
    ));

    let (input, expr) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(expr), None)))
}

fn parse_or(input: &str) -> IResult<&str, Node<Or>> {
    let (input, initial) = parse_and(input)?;
    
    let mut extended_parser = many0(preceded(
        ws(tag("||")),
        parse_and,
    ));
    let (input, extended) = extended_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Or { initial, extended }),
        None
    )))
}

fn parse_and(input: &str) -> IResult<&str, Node<And>> {
    let (input, initial) = parse_relation(input)?;
    
    let mut extended_parser = many0(preceded(
        ws(tag("&&")),
        parse_relation,
    ));
    let (input, extended) = extended_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(And { initial, extended }),
        None
    )))
}

fn parse_relation(input: &str) -> IResult<&str, Node<Relation>> {
    let (input, initial) = parse_add(input)?;
    
    let mut parser = alt((
        map(
            preceded(ws(tag("has")), parse_add),
            |field| Relation::Has {
                target: initial.clone(),
                field,
            },
        ),
        map(
            preceded(ws(tag("like")), parse_add),
            |pattern| Relation::Like {
                target: initial.clone(),
                pattern,
            },
        ),
        map(
            tuple((
                ws(tag("is")),
                parse_add,
                opt(preceded(ws(tag("in")), parse_add)),
            )),
            |(_, entity_type, in_entity)| {
                Relation::IsIn {
                    target: initial.clone(),
                    entity_type,
                    in_entity,
                }
            },
        ),
        map(
            many0(tuple((ws(parse_rel_op), parse_add))),
            |extended| Relation::Common { initial: initial.clone(), extended },
        ),
    ));

    let (input, relation) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(relation), None)))
}

fn parse_rel_op(input: &str) -> IResult<&str, RelOp> {
    let mut parser = alt((
        map(tag("<="), |_| RelOp::LessEq),
        map(tag(">="), |_| RelOp::GreaterEq),
        map(tag("<"), |_| RelOp::Less),
        map(tag(">"), |_| RelOp::Greater),
        map(tag("!="), |_| RelOp::NotEq),
        map(tag("=="), |_| RelOp::Eq),
        map(tag("="), |_| RelOp::InvalidSingleEq),
        map(tag("in"), |_| RelOp::In),
    ));

    parser.parse(input)
}

fn parse_add(input: &str) -> IResult<&str, Node<Add>> {
    let (input, initial) = parse_mult(input)?;
    
    let mut extended_parser = many0(tuple((
        ws(parse_add_op),
        parse_mult,
    )));
    let (input, extended) = extended_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Add { initial, extended }),
        None
    )))
}

fn parse_add_op(input: &str) -> IResult<&str, AddOp> {
    let mut parser = alt((
        map(char('+'), |_| AddOp::Plus),
        map(char('-'), |_| AddOp::Minus),
    ));

    parser.parse(input)
}

fn parse_mult(input: &str) -> IResult<&str, Node<Mult>> {
    let (input, initial) = parse_unary(input)?;
    
    let mut extended_parser = many0(tuple((
        ws(parse_mult_op),
        parse_unary,
    )));
    let (input, extended) = extended_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Mult { initial, extended }),
        None
    )))
}

fn parse_mult_op(input: &str) -> IResult<&str, MultOp> {
    let mut parser = alt((
        map(char('*'), |_| MultOp::Times),
        map(char('/'), |_| MultOp::Divide),
        map(char('%'), |_| MultOp::Mod),
    ));

    parser.parse(input)
}

fn parse_unary(input: &str) -> IResult<&str, Node<Unary>> {
    let mut op_parser = opt(alt((
        map(many1(char('!')), |v| {
            match v.len() {
                1..=4 => NegOp::Bang(v.len() as u8),
                _ => NegOp::OverBang,
            }
        }),
        map(many1(char('-')), |v| {
            match v.len() {
                1..=4 => NegOp::Dash(v.len() as u8),
                _ => NegOp::OverDash,
            }
        }),
    )));
    
    let (input, op) = op_parser.parse(input)?;
    let (input, item) = parse_member(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Unary { op, item }),
        None
    )))
}

fn parse_member(input: &str) -> IResult<&str, Node<Member>> {
    let (input, item) = parse_primary(input)?;
    
    let mut access_parser = many0(parse_mem_access);
    let (input, access) = access_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Member { item, access }),
        None
    )))
}

fn parse_mem_access(input: &str) -> IResult<&str, Node<MemAccess>> {
    let mut parser = alt((
        map(
            preceded(ws(char('.')), parse_ident),
            MemAccess::Field,
        ),
        map(
            delimited(
                ws(char('(')),
                separated_list0(ws(char(',')), parse_expr),
                ws(char(')')),
            ),
            MemAccess::Call,
        ),
        map(
            delimited(
                ws(char('[')),
                parse_expr,
                ws(char(']')),
            ),
            MemAccess::Index,
        ),
    ));

    let (input, mem_access) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(mem_access), None)))
}

fn parse_primary(input: &str) -> IResult<&str, Node<Primary>> {
    let mut parser = alt((
        map(parse_literal, Primary::Literal),
        map(parse_ref, Primary::Ref),
        map(parse_name, Primary::Name),
        map(parse_slot, Primary::Slot),
        map(
            delimited(ws(char('(')), parse_expr, ws(char(')'))),
            Primary::Expr,
        ),
        map(
            delimited(
                ws(char('[')),
                separated_list0(ws(char(',')), parse_expr),
                ws(char(']')),
            ),
            Primary::EList,
        ),
        map(
            delimited(
                ws(char('{')),
                separated_list0(ws(char(',')), parse_rec_init),
                ws(char('}')),
            ),
            Primary::RInits,
        ),
    ));

    let (input, primary) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(primary), None)))
}

fn parse_literal(input: &str) -> IResult<&str, Node<Literal>> {
    let mut parser = alt((
        map(tag("true"), |_| Literal::True),
        map(tag("false"), |_| Literal::False),
        map(parse_number, Literal::Num),
        map(parse_str, |s| Literal::Str(s)),
    ));

    let (input, literal) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(literal), None)))
}

fn parse_number(input: &str) -> IResult<&str, u64> {
    let mut parser = map_res(
        recognize(many1(terminated(one_of("0123456789"), many0(char('_'))))),
        |s: &str| s.replace('_', "").parse(),
    );

    parser.parse(input)
}

fn parse_name(input: &str) -> IResult<&str, Node<Name>> {
    let mut path_parser = many0(terminated(
        parse_ident,
        ws(tag("::")),
    ));
    
    let (input, path) = path_parser.parse(input)?;
    let (input, name) = parse_ident(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Name { path, name }),
        None
    )))
}

fn parse_slot(input: &str) -> IResult<&str, Node<Slot>> {
    let mut parser = alt((
        map(tag("?principal"), |_| Slot::Principal),
        map(tag("?resource"), |_| Slot::Resource),
        map(
            preceded(
                char('?'),
                recognize(pair(
                    alt((alpha1, tag("_"))),
                    many0(alt((alphanumeric1, tag("_")))),
                )),
            ),
            |s: &str| Slot::Other(SmolStr::new(s)),
        ),
    ));

    let (input, slot) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(slot), None)))
}

fn parse_ref(input: &str) -> IResult<&str, Node<Ref>> {
    let (input, path) = parse_name(input)?;
    
    let mut separator_parser = ws(tag("::"));
    let (input, _) = separator_parser.parse(input)?;
    
    let mut parser = alt((
        map(
            parse_str,
            |eid| Ref::Uid { path: path.clone(), eid },
        ),
        map(
            delimited(
                ws(char('{')),
                separated_list0(ws(char(',')), parse_ref_init),
                ws(char('}')),
            ),
            |rinits| Ref::Ref { path: path.clone(), rinits },
        ),
    ));

    let (input, ref_val) = parser.parse(input)?;
    Ok((input, Node::with_maybe_source_loc(Some(ref_val), None)))
}

fn parse_ref_init(input: &str) -> IResult<&str, Node<RefInit>> {
    let (input, ident) = parse_ident(input)?;
    
    let mut colon_parser = ws(char(':'));
    let (input, _) = colon_parser.parse(input)?;
    
    let (input, literal) = parse_literal(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(RefInit(ident, literal)),
        None
    )))
}

fn parse_rec_init(input: &str) -> IResult<&str, Node<RecInit>> {
    let (input, expr1) = parse_expr(input)?;
    
    let mut colon_parser = ws(char(':'));
    let (input, _) = colon_parser.parse(input)?;
    
    let (input, expr2) = parse_expr(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(RecInit(expr1, expr2)),
        None
    )))
}

fn parse_variable_def(input: &str) -> IResult<&str, Node<VariableDef>> {
    let (input, variable) = parse_ident(input)?;
    
    let mut type_parser = opt(preceded(
        ws(char(':')),
        parse_name,
    ));
    let (input, unused_type_name) = type_parser.parse(input)?;
    
    let mut entity_parser = opt(preceded(
        ws(tag("is")),
        parse_add,
    ));
    let (input, entity_type) = entity_parser.parse(input)?;
    
    let mut ineq_parser = opt(tuple((
        ws(parse_rel_op),
        parse_expr,
    )));
    let (input, ineq) = ineq_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(VariableDef {
            variable,
            unused_type_name,
            entity_type,
            ineq,
        }),
        None
    )))
}

fn parse_cond(input: &str) -> IResult<&str, Node<Cond>> {
    let (input, cond) = parse_ident(input)?;
    
    let mut expr_parser = delimited(
        ws(char('{')),
        opt(parse_expr),
        ws(char('}')),
    );
    let (input, expr) = expr_parser.parse(input)?;

    Ok((input, Node::with_maybe_source_loc(
        Some(Cond { cond, expr }),
        None
    )))
}

pub fn parse_policy_file(input: &str) -> Result<Node<cst::Policies>, String> {
    let mut parser = all_consuming(map(
        many0(ws(parse_policy)),
        |policies| Node::with_maybe_source_loc(
            Some(cst::Policies(policies)),
            None
        ),
    ));

    match parser.parse(input) {
        Ok((_, node)) => Ok(node),
        Err(e) => Err("fail".to_string()),
    }
}

