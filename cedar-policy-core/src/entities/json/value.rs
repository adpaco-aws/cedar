/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use super::{
    AttributeType, JsonDeserializationError, JsonDeserializationErrorContext,
    JsonSerializationError, SchemaType,
};
use crate::ast::{
    BorrowedRestrictedExpr, Eid, EntityUID, Expr, ExprConstructionError, ExprKind, Literal, Name,
    RestrictedExpr,
};
use crate::entities::EscapeKind;
use crate::extensions::{ExtensionFunctionLookupError, Extensions};
use crate::FromNormalizedStr;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};

/// The canonical JSON representation of a Cedar value.
/// Many Cedar values have a natural one-to-one mapping to and from JSON values.
/// Cedar values of some types, like entity references or extension values,
/// cannot easily be represented in JSON and thus are represented using the
/// `__expr`, `__entity`, or `__extn` escapes.
///
/// For example, this is the JSON format for attribute values expected by
/// `EntityJsonParser`, when schema-based parsing is not used.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CedarValueJson {
    /// Special JSON object with single reserved "__expr" key:
    /// interpret the following string as a (restricted) Cedar expression.
    /// Some escape (this or the following ones) is necessary for extension
    /// values and entity references, but this `__expr` escape could also be
    /// used for any other values.
    ///
    /// `__expr` is deprecated (starting with the 1.2 release) and will be
    /// removed in favor of `__entity` and `__extn`, which together cover all of
    /// the use-cases where `__expr` would have been necessary.
    //
    // listed before `Record` so that it takes priority: otherwise, the escape
    // would be interpreted as a Record with a key "__expr". see docs on
    // `serde(untagged)`
    ExprEscape {
        /// String to interpret as a (restricted) Cedar expression
        __expr: SmolStr,
    },
    /// Special JSON object with single reserved "__entity" key:
    /// the following item should be a JSON object of the form
    /// `{ "type": "xxx", "id": "yyy" }`.
    /// Some escape (this or `__expr`, which is deprecated) is necessary for
    /// entity references.
    //
    // listed before `Record` so that it takes priority: otherwise, the escape
    // would be interpreted as a Record with a key "__entity". see docs on
    // `serde(untagged)`
    EntityEscape {
        /// JSON object containing the entity type and ID
        __entity: TypeAndId,
    },
    /// Special JSON object with single reserved "__extn" key:
    /// the following item should be a JSON object of the form
    /// `{ "fn": "xxx", "arg": "yyy" }`.
    /// Some escape (this or `__expr`, which is deprecated) is necessary for
    /// extension values.
    //
    // listed before `Record` so that it takes priority: otherwise, the escape
    // would be interpreted as a Record with a key "__extn". see docs on
    // `serde(untagged)`
    ExtnEscape {
        /// JSON object containing the extension-constructor call
        __extn: FnAndArg,
    },
    /// JSON bool => Cedar bool
    Bool(bool),
    /// JSON int => Cedar long (64-bit signed integer)
    Long(i64),
    /// JSON string => Cedar string
    String(SmolStr),
    /// JSON list => Cedar set; can contain any `CedarValueJson`s, even
    /// heterogeneously
    Set(Vec<CedarValueJson>),
    /// JSON object => Cedar record; must have string keys, but values
    /// can be any JSONValues, even heterogeneously
    Record(JsonRecord),
}

/// Structure representing a Cedar record in JSON
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct JsonRecord {
    /// Cedar records must have string keys, but values can be any
    /// `CedarValueJson`s, even heterogeneously
    #[serde_as(as = "serde_with::MapPreventDuplicates<_, _>")]
    #[serde(flatten)]
    values: BTreeMap<SmolStr, CedarValueJson>,
}

impl IntoIterator for JsonRecord {
    type Item = (SmolStr, CedarValueJson);
    type IntoIter = <BTreeMap<SmolStr, CedarValueJson> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a> IntoIterator for &'a JsonRecord {
    type Item = (&'a SmolStr, &'a CedarValueJson);
    type IntoIter = <&'a BTreeMap<SmolStr, CedarValueJson> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

// At this time, this doesn't check for duplicate keys upon constructing a
// `JsonRecord` from an iterator.
// As of this writing, we only construct `JsonRecord` from an iterator during
// _serialization_, not _deserialization_, and we can assume that values being
// serialized (i.e., coming from the Cedar engine itself) are already free of
// duplicate keys.
impl FromIterator<(SmolStr, CedarValueJson)> for JsonRecord {
    fn from_iter<T: IntoIterator<Item = (SmolStr, CedarValueJson)>>(iter: T) -> Self {
        Self {
            values: BTreeMap::from_iter(iter),
        }
    }
}

impl JsonRecord {
    /// Iterate over the (k, v) pairs in the record
    pub fn iter<'s>(&'s self) -> impl Iterator<Item = (&'s SmolStr, &'s CedarValueJson)> {
        self.values.iter()
    }

    /// Get the number of attributes in the record
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

/// Structure expected by the `__entity` escape
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TypeAndId {
    /// Entity typename
    #[serde(rename = "type")]
    entity_type: SmolStr,
    /// Entity id
    id: SmolStr,
}

impl From<EntityUID> for TypeAndId {
    fn from(euid: EntityUID) -> TypeAndId {
        let (entity_type, eid) = euid.components();
        TypeAndId {
            entity_type: entity_type.to_string().into(),
            id: AsRef::<str>::as_ref(&eid).into(),
        }
    }
}

impl From<&EntityUID> for TypeAndId {
    fn from(euid: &EntityUID) -> TypeAndId {
        TypeAndId {
            entity_type: euid.entity_type().to_string().into(),
            id: AsRef::<str>::as_ref(&euid.eid()).into(),
        }
    }
}

impl TryFrom<TypeAndId> for EntityUID {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(e: TypeAndId) -> Result<EntityUID, Self::Error> {
        Ok(EntityUID::from_components(
            Name::from_normalized_str(&e.entity_type)?,
            Eid::new(e.id),
        ))
    }
}

/// Structure expected by the `__extn` escape
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FnAndArg {
    /// Extension constructor function
    #[serde(rename = "fn")]
    pub(crate) ext_fn: SmolStr,
    /// Argument to that constructor
    pub(crate) arg: Box<CedarValueJson>,
}

impl CedarValueJson {
    /// Encode the given `EntityUID` as a `CedarValueJson`
    pub fn uid(euid: &EntityUID) -> Self {
        Self::EntityEscape {
            __entity: TypeAndId::from(euid.clone()),
        }
    }

    /// Convert this `CedarValueJson` into a Cedar "restricted expression"
    pub fn into_expr(
        self,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        match self {
            Self::Bool(b) => Ok(RestrictedExpr::val(b)),
            Self::Long(i) => Ok(RestrictedExpr::val(i)),
            Self::String(s) => Ok(RestrictedExpr::val(s)),
            Self::Set(vals) => Ok(RestrictedExpr::set(
                vals.into_iter()
                    .map(|v| v.into_expr(ctx.clone()))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Self::Record(map) => Ok(RestrictedExpr::record(
                map.into_iter()
                    .map(|(k, v)| Ok((k, v.into_expr(ctx.clone())?)))
                    .collect::<Result<Vec<_>, JsonDeserializationError>>()?,
            )
            .map_err(|e| match e {
                ExprConstructionError::DuplicateKeyInRecordLiteral { key } => {
                    JsonDeserializationError::DuplicateKeyInRecordLiteral {
                        ctx: Box::new(ctx()),
                        key,
                    }
                }
            })?),
            Self::ExprEscape { __expr: expr } => {
                use crate::parser;
                let expr: Expr = parser::parse_expr(&expr).map_err(|errs| {
                    JsonDeserializationError::ParseEscape {
                        kind: EscapeKind::Expr,
                        value: expr.to_string(),
                        errs,
                    }
                })?;
                Ok(RestrictedExpr::new(expr)?)
            }
            Self::EntityEscape { __entity: entity } => Ok(RestrictedExpr::val(
                EntityUID::try_from(entity.clone()).map_err(|errs| {
                    JsonDeserializationError::ParseEscape {
                        kind: EscapeKind::Entity,
                        value: serde_json::to_string_pretty(&entity)
                            .unwrap_or_else(|_| format!("{:?}", &entity)),
                        errs,
                    }
                })?,
            )),
            Self::ExtnEscape { __extn: extn } => extn.into_expr(ctx),
        }
    }

    /// Convert a Cedar "restricted expression" into a `CedarValueJson`.
    pub fn from_expr(expr: BorrowedRestrictedExpr<'_>) -> Result<Self, JsonSerializationError> {
        match expr.as_ref().expr_kind() {
            ExprKind::Lit(lit) => Ok(Self::from_lit(lit.clone())),
            ExprKind::ExtensionFunctionApp { fn_name, args } => match args.len() {
                0 => Err(JsonSerializationError::ExtnCall0Arguments {
                    func: fn_name.clone(),
                }),
                // PANIC SAFETY. We've checked that `args` is of length 1, fine to index at 0
                #[allow(clippy::indexing_slicing)]
                1 => Ok(Self::ExtnEscape {
                    __extn: FnAndArg {
                        ext_fn: fn_name.to_string().into(),
                        arg: Box::new(CedarValueJson::from_expr(
                            // assuming the invariant holds for `expr`, it must also hold here
                            BorrowedRestrictedExpr::new_unchecked(
                                &args[0], // checked above that |args| == 1
                            ),
                        )?),
                    },
                }),
                _ => Err(JsonSerializationError::ExtnCall2OrMoreArguments {
                    func: fn_name.clone(),
                }),
            },
            ExprKind::Set(exprs) => Ok(Self::Set(
                exprs
                    .iter()
                    .map(BorrowedRestrictedExpr::new_unchecked) // assuming the invariant holds for `expr`, it must also hold here
                    .map(CedarValueJson::from_expr)
                    .collect::<Result<_, JsonSerializationError>>()?,
            )),
            ExprKind::Record(map) => {
                // if `map` contains a key which collides with one of our JSON
                // escapes, then we have a problem because it would be interpreted
                // as an escape when being read back in.
                // We could be a little more permissive here, but to be
                // conservative, we throw an error for any record that contains
                // any key with a reserved name, not just single-key records
                // with the reserved names.
                let reserved_keys: HashSet<&str> =
                    HashSet::from_iter(["__entity", "__extn", "__expr"]);
                let collision = map.keys().find(|k| reserved_keys.contains(k.as_str()));
                if let Some(collision) = collision {
                    Err(JsonSerializationError::ReservedKey {
                        key: collision.clone(),
                    })
                } else {
                    // the common case: the record doesn't use any reserved keys
                    Ok(Self::Record(
                        map.iter()
                            .map(|(k, v)| {
                                Ok((
                                    k.clone(),
                                    CedarValueJson::from_expr(
                                        // assuming the invariant holds for `expr`, it must also hold here
                                        BorrowedRestrictedExpr::new_unchecked(v),
                                    )?,
                                ))
                            })
                            .collect::<Result<_, JsonSerializationError>>()?,
                    ))
                }
            }
            kind => {
                Err(JsonSerializationError::UnexpectedRestrictedExprKind { kind: kind.clone() })
            }
        }
    }

    /// Convert a Cedar literal into a `CedarValueJson`.
    pub fn from_lit(lit: Literal) -> Self {
        match lit {
            Literal::Bool(b) => Self::Bool(b),
            Literal::Long(i) => Self::Long(i),
            Literal::String(s) => Self::String(s),
            Literal::EntityUID(euid) => Self::EntityEscape {
                __entity: (*euid).clone().into(),
            },
        }
    }
}

impl FnAndArg {
    /// Convert this `FnAndArg` into a Cedar "restricted expression" (which will be a call to an extension constructor)
    pub fn into_expr(
        self,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        Ok(RestrictedExpr::call_extension_fn(
            Name::from_normalized_str(&self.ext_fn).map_err(|errs| {
                JsonDeserializationError::ParseEscape {
                    kind: EscapeKind::Extension,
                    value: self.ext_fn.to_string(),
                    errs,
                }
            })?,
            vec![CedarValueJson::into_expr(*self.arg, ctx)?],
        ))
    }
}

/// Struct used to parse Cedar values from JSON.
#[derive(Debug, Clone)]
pub struct ValueParser<'e> {
    /// Extensions which are active for the JSON parsing.
    extensions: Extensions<'e>,
}

impl<'e> ValueParser<'e> {
    /// Create a new `ValueParser`.
    pub fn new(extensions: Extensions<'e>) -> Self {
        Self { extensions }
    }

    /// internal function that converts a Cedar value (in JSON) into a
    /// `RestrictedExpr`. Performs schema-based parsing if `expected_ty` is
    /// provided.
    pub fn val_into_rexpr(
        &self,
        val: serde_json::Value,
        expected_ty: Option<&SchemaType>,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        match expected_ty {
            // The expected type is an entity reference. Special parsing rules
            // apply: for instance, the `__entity` escape can optionally be omitted.
            // What this means is that we parse the contents as `EntityUidJson`, and
            // then convert that into an entity reference `RestrictedExpr`
            Some(SchemaType::Entity { .. }) => {
                let uidjson: EntityUidJson = serde_json::from_value(val)?;
                Ok(RestrictedExpr::val(uidjson.into_euid(ctx)?))
            }
            // The expected type is an extension type. Special parsing rules apply:
            // for instance, the `__extn` escape can optionally be omitted. What
            // this means is that we parse the contents as `ExtnValueJson`, and then
            // convert that into an extension-function-call `RestrictedExpr`
            Some(SchemaType::Extension { ref name, .. }) => {
                let extjson: ExtnValueJson = serde_json::from_value(val)?;
                self.extn_value_json_into_rexpr(extjson, name.clone(), ctx)
            }
            // The expected type is a set type. No special parsing rules apply, but
            // we need to parse the elements according to the expected element type
            Some(expected_ty @ SchemaType::Set { element_ty }) => match val {
                serde_json::Value::Array(elements) => Ok(RestrictedExpr::set(
                    elements
                        .into_iter()
                        .map(|element| self.val_into_rexpr(element, Some(element_ty), ctx.clone()))
                        .collect::<Result<Vec<RestrictedExpr>, JsonDeserializationError>>()?,
                )),
                _ => Err(JsonDeserializationError::TypeMismatch {
                    ctx: Box::new(ctx()),
                    expected: Box::new(expected_ty.clone()),
                    actual: {
                        let jvalue: CedarValueJson = serde_json::from_value(val)?;
                        Box::new(
                            self.type_of_rexpr(jvalue.into_expr(ctx.clone())?.as_borrowed(), ctx)?,
                        )
                    },
                }),
            },
            // The expected type is a record type. No special parsing rules
            // apply, but we need to parse the attribute values according to
            // their expected element types
            Some(
                expected_ty @ SchemaType::Record {
                    attrs: expected_attrs,
                },
            ) => match val {
                serde_json::Value::Object(mut actual_attrs) => {
                    let ctx2 = ctx.clone(); // for borrow-check, so the original `ctx` can be moved into the closure below
                    let mut_actual_attrs = &mut actual_attrs; // for borrow-check, so only a mut ref gets moved into the closure, and we retain ownership of `actual_attrs`
                    let rexpr_pairs = expected_attrs
                        .iter()
                        .filter_map(move |(k, expected_attr_ty)| {
                            match mut_actual_attrs.remove(k.as_str()) {
                                Some(actual_attr) => {
                                    match self.val_into_rexpr(actual_attr, Some(expected_attr_ty.schema_type()), ctx.clone()) {
                                        Ok(actual_attr) => Some(Ok((k.clone(), actual_attr))),
                                        Err(e) => Some(Err(e)),
                                    }
                                }
                                None if expected_attr_ty.is_required() => Some(Err(JsonDeserializationError::MissingRequiredRecordAttr {
                                    ctx: Box::new(ctx()),
                                    record_attr: k.clone(),
                                })),
                                None => None,
                            }
                        })
                        .collect::<Result<Vec<(SmolStr, RestrictedExpr)>, JsonDeserializationError>>()?;
                    // we've now checked that all expected attrs exist, and removed them from `actual_attrs`.
                    // we still need to verify that we didn't have any unexpected attrs.
                    if let Some((record_attr, _)) = actual_attrs.into_iter().next() {
                        return Err(JsonDeserializationError::UnexpectedRecordAttr {
                            ctx: Box::new(ctx2()),
                            record_attr: record_attr.into(),
                        });
                    }
                    // having duplicate keys should be impossible here (because
                    // neither `actual_attrs` nor `expected_attrs` can have
                    // duplicate keys; they're both maps), but we can still throw
                    // the error properly in the case that it somehow happens
                    RestrictedExpr::record(rexpr_pairs).map_err(|e| match e {
                        ExprConstructionError::DuplicateKeyInRecordLiteral { key } => {
                            JsonDeserializationError::DuplicateKeyInRecordLiteral {
                                ctx: Box::new(ctx2()),
                                key,
                            }
                        }
                    })
                }
                _ => Err(JsonDeserializationError::TypeMismatch {
                    ctx: Box::new(ctx()),
                    expected: Box::new(expected_ty.clone()),
                    actual: {
                        let jvalue: CedarValueJson = serde_json::from_value(val)?;
                        Box::new(
                            self.type_of_rexpr(jvalue.into_expr(ctx.clone())?.as_borrowed(), ctx)?,
                        )
                    },
                }),
            },
            // The expected type is any other type, or we don't have an expected type.
            // No special parsing rules apply; we do ordinary, non-schema-based parsing.
            Some(_) | None => {
                // Everything is parsed as `CedarValueJson`, and converted into
                // `RestrictedExpr` from that.
                let jvalue: CedarValueJson = serde_json::from_value(val)?;
                Ok(jvalue.into_expr(ctx)?)
            }
        }
    }

    /// internal function that converts an `ExtnValueJson` into a
    /// `RestrictedExpr`, which will be an extension constructor call.
    ///
    /// `expected_typename`: Specific extension type that is expected.
    fn extn_value_json_into_rexpr(
        &self,
        extnjson: ExtnValueJson,
        expected_typename: Name,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        match extnjson {
            ExtnValueJson::ExplicitExprEscape { __expr } => {
                // reuse the same logic that parses CedarValueJson
                let jvalue = CedarValueJson::ExprEscape { __expr };
                let expr = jvalue.into_expr(ctx.clone())?;
                match expr.expr_kind() {
                    ExprKind::ExtensionFunctionApp { .. } => Ok(expr),
                    _ => Err(JsonDeserializationError::ExpectedExtnValue {
                        ctx: Box::new(ctx()),
                        got: Box::new(expr.clone().into()),
                    }),
                }
            }
            ExtnValueJson::ExplicitExtnEscape { __extn }
            | ExtnValueJson::ImplicitExtnEscape(__extn) => {
                // reuse the same logic that parses CedarValueJson
                let jvalue = CedarValueJson::ExtnEscape { __extn };
                let expr = jvalue.into_expr(ctx.clone())?;
                match expr.expr_kind() {
                    ExprKind::ExtensionFunctionApp { .. } => Ok(expr),
                    _ => Err(JsonDeserializationError::ExpectedExtnValue {
                        ctx: Box::new(ctx()),
                        got: Box::new(expr.clone().into()),
                    }),
                }
            }
            ExtnValueJson::ImplicitConstructor(val) => {
                let arg = val.into_expr(ctx.clone())?;
                let argty = self.type_of_rexpr(arg.as_borrowed(), ctx.clone())?;
                let func = self
                    .extensions
                    .lookup_single_arg_constructor(
                        &SchemaType::Extension {
                            name: expected_typename.clone(),
                        },
                        &argty,
                    )?
                    .ok_or_else(|| JsonDeserializationError::MissingImpliedConstructor {
                        ctx: Box::new(ctx()),
                        return_type: Box::new(SchemaType::Extension {
                            name: expected_typename,
                        }),
                        arg_type: Box::new(argty.clone()),
                    })?;
                Ok(RestrictedExpr::call_extension_fn(
                    func.name().clone(),
                    vec![arg],
                ))
            }
        }
    }

    /// Get the `SchemaType` of a restricted expression.
    ///
    /// This isn't possible for general `Expr`s (without a Request, full schema,
    /// etc), but is possible for restricted expressions, given the information
    /// in `Extensions`.
    pub fn type_of_rexpr(
        &self,
        rexpr: BorrowedRestrictedExpr<'_>,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<SchemaType, JsonDeserializationError> {
        match rexpr.expr_kind() {
            ExprKind::Lit(Literal::Bool(_)) => Ok(SchemaType::Bool),
            ExprKind::Lit(Literal::Long(_)) => Ok(SchemaType::Long),
            ExprKind::Lit(Literal::String(_)) => Ok(SchemaType::String),
            ExprKind::Lit(Literal::EntityUID(uid)) => Ok(SchemaType::Entity { ty: uid.entity_type().clone() }),
            ExprKind::Set(elements) => {
                let mut element_types = elements.iter().map(|el| {
                    self.type_of_rexpr(BorrowedRestrictedExpr::new_unchecked(el), ctx.clone()) // assuming the invariant holds for the set as a whole, it will also hold for each element
                });
                match element_types.next() {
                    None => Ok(SchemaType::EmptySet),
                    Some(Err(e)) => Err(e),
                    Some(Ok(element_ty)) => {
                        let matches_element_ty = |ty: &Result<SchemaType, JsonDeserializationError>| matches!(ty, Ok(ty) if ty.is_consistent_with(&element_ty));
                        let conflicting_ty = element_types.find(|ty| !matches_element_ty(ty));
                        match conflicting_ty {
                            None => Ok(SchemaType::Set { element_ty: Box::new(element_ty) }),
                            Some(Ok(conflicting_ty)) =>
                                Err(JsonDeserializationError::HeterogeneousSet {
                                    ctx: Box::new(ctx()),
                                    ty1: Box::new(element_ty),
                                    ty2: Box::new(conflicting_ty),
                                }),
                            Some(Err(e)) => Err(e),
                        }
                    }
                }
            }
            ExprKind::Record(map) => {
                Ok(SchemaType::Record { attrs: {
                    map.iter().map(|(k, v)| {
                        let attr_type = self.type_of_rexpr(
                            BorrowedRestrictedExpr::new_unchecked(v), // assuming the invariant holds for the record as a whole, it will also hold for each attribute value
                            ctx.clone(),
                        )?;
                        // we can't know if the attribute is required or optional,
                        // but marking it optional is more flexible -- allows the
                        // attribute type to `is_consistent_with()` more types
                        Ok((k.clone(), AttributeType::optional(attr_type)))
                    }).collect::<Result<HashMap<_,_>, JsonDeserializationError>>()?
                }})
            }
            ExprKind::ExtensionFunctionApp { fn_name, .. } => {
                let efunc = self.extensions.func(fn_name)?;
                Ok(efunc.return_type().cloned().ok_or_else(|| ExtensionFunctionLookupError::HasNoType {
                    name: efunc.name().clone()
                })?)
            }
            // PANIC SAFETY. Unreachable by invariant on restricted expressions
            #[allow(clippy::unreachable)]
            expr => unreachable!("internal invariant violation: BorrowedRestrictedExpr somehow contained this expr case: {expr:?}"),
        }
    }
}

/// Serde JSON format for Cedar values where we know we're expecting an entity
/// reference
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EntityUidJson {
    /// Explicit `__expr` escape; see notes on `CedarValueJson::ExprEscape`.
    ///
    /// Deprecated since the 1.2 release; use
    /// `{ "__entity": { "type": "...", "id": "..." } }` instead.
    ExplicitExprEscape {
        /// String to interpret as a (restricted) Cedar expression.
        /// In this case, it must evaluate to an entity reference.
        __expr: SmolStr,
    },
    /// Explicit `__entity` escape; see notes on `CedarValueJson::EntityEscape`
    ExplicitEntityEscape {
        /// JSON object containing the entity type and ID
        __entity: TypeAndId,
    },
    /// Implicit `__expr` escape, in which case we'll just see a JSON string.
    ///
    /// Deprecated since the 1.2 release; use
    /// `{ "type": "...", "id": "..." }` instead.
    ImplicitExprEscape(SmolStr),
    /// Implicit `__entity` escape, in which case we'll see just the TypeAndId
    /// structure
    ImplicitEntityEscape(TypeAndId),
}

/// Serde JSON format for Cedar values where we know we're expecting an
/// extension value
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExtnValueJson {
    /// Explicit `__expr` escape; see notes on `CedarValueJson::ExprEscape`.
    ///
    /// Deprecated since the 1.2 release; use
    /// `{ "__extn": { "fn": "...", "arg": "..." } }` instead.
    ExplicitExprEscape {
        /// String to interpret as a (restricted) Cedar expression.
        /// In this case, it must evaluate to an extension value.
        __expr: SmolStr,
    },
    /// Explicit `__extn` escape; see notes on `CedarValueJson::ExtnEscape`
    ExplicitExtnEscape {
        /// JSON object containing the extension-constructor call
        __extn: FnAndArg,
    },
    /// Implicit `__extn` escape, in which case we'll just see the `FnAndArg`
    /// directly
    ImplicitExtnEscape(FnAndArg),
    /// Implicit `__extn` escape and constructor. Constructor is implicitly
    /// selected based on the argument type and the expected type.
    //
    // This is listed last so that it has lowest priority when deserializing.
    // If one of the above forms fits, we use that.
    ImplicitConstructor(CedarValueJson),
}

impl EntityUidJson {
    /// Construct an `EntityUidJson` from entity type name and eid.
    ///
    /// This will use the `ImplicitEntityEscape` form, if it matters.
    pub fn new(entity_type: impl Into<SmolStr>, id: impl Into<SmolStr>) -> Self {
        Self::ImplicitEntityEscape(TypeAndId {
            entity_type: entity_type.into(),
            id: id.into(),
        })
    }

    /// Convert this `EntityUidJson` into an `EntityUID`
    pub fn into_euid(
        self,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<EntityUID, JsonDeserializationError> {
        let is_implicit_expr = matches!(self, Self::ImplicitExprEscape(_));
        match self {
            Self::ExplicitExprEscape { __expr } | Self::ImplicitExprEscape(__expr) => {
                // reuse the same logic that parses CedarValueJson
                let jvalue = CedarValueJson::ExprEscape {
                    __expr: __expr.clone(),
                };
                let expr = jvalue.into_expr(ctx.clone()).map_err(|e| {
                    if is_implicit_expr {
                        // in this case, the user provided a string that wasn't
                        // an appropriate entity reference.
                        // Perhaps they didn't realize they needed to provide an
                        // entity reference at all, or perhaps they just had an
                        // entity syntax error.
                        // We'll give them the `ExpectedLiteralEntityRef` error
                        // message instead of the `ExprParseError` error message,
                        // as it's likely to be more helpful in my opinion
                        // PANIC SAFETY: Every `String` can be turned into a restricted expression
                        #[allow(clippy::unwrap_used)]
                        JsonDeserializationError::ExpectedLiteralEntityRef {
                            ctx: Box::new(ctx()),
                            got: Box::new(
                                CedarValueJson::String(__expr)
                                    .into_expr(ctx.clone())
                                    .unwrap()
                                    .into(),
                            ),
                        }
                    } else {
                        e
                    }
                })?;
                match expr.expr_kind() {
                    ExprKind::Lit(Literal::EntityUID(euid)) => Ok((**euid).clone()),
                    _ => Err(JsonDeserializationError::ExpectedLiteralEntityRef {
                        ctx: Box::new(ctx()),
                        got: Box::new(expr.clone().into()),
                    }),
                }
            }
            Self::ExplicitEntityEscape { __entity } | Self::ImplicitEntityEscape(__entity) => {
                // reuse the same logic that parses CedarValueJson
                let jvalue = CedarValueJson::EntityEscape { __entity };
                let expr = jvalue.into_expr(ctx.clone())?;
                match expr.expr_kind() {
                    ExprKind::Lit(Literal::EntityUID(euid)) => Ok((**euid).clone()),
                    _ => Err(JsonDeserializationError::ExpectedLiteralEntityRef {
                        ctx: Box::new(ctx()),
                        got: Box::new(expr.clone().into()),
                    }),
                }
            }
        }
    }
}

/// Convert an `EntityUID` to `EntityUidJson`, using the `ExplicitEntityEscape` option
impl From<EntityUID> for EntityUidJson {
    fn from(uid: EntityUID) -> EntityUidJson {
        EntityUidJson::ExplicitEntityEscape {
            __entity: uid.into(),
        }
    }
}

/// Convert an `EntityUID` to `EntityUidJson`, using the `ExplicitEntityEscape` option
impl From<&EntityUID> for EntityUidJson {
    fn from(uid: &EntityUID) -> EntityUidJson {
        EntityUidJson::ExplicitEntityEscape {
            __entity: uid.into(),
        }
    }
}