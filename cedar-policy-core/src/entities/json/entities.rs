/*
 * Copyright Cedar Contributors
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
    err::{JsonDeserializationError, JsonDeserializationErrorContext, JsonSerializationError},
    CedarValueJson, EntityTypeDescription, EntityUidJson, NoEntitiesSchema, Schema, TypeAndId,
    ValueParser,
};
use crate::ast::{BorrowedRestrictedExpr, Entity, EntityUID, PartialValue, RestrictedExpr};
use crate::entities::conformance::EntitySchemaConformanceChecker;
use crate::entities::{
    conformance::err::{EntitySchemaConformanceError, UnexpectedEntityTypeError},
    Entities, EntitiesError, TCComputation,
};
use crate::extensions::Extensions;
use crate::jsonvalue::JsonValueWithNoDuplicateKeys;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    io::Read,
};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Serde JSON format for a single entity
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct EntityJson {
    /// UID of the entity, specified in any form accepted by `EntityUidJson`
    uid: EntityUidJson,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `CedarValueJson`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJson` if we're expecting an entity reference,
    /// so for now we leave it in its raw json-value form, albeit not allowing
    /// any duplicate keys in any records that may occur in an attribute value
    /// (even nested).)
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, CedarValueJson>"))]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in attribute values (including recursively)
    attrs: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
    /// Parents of the entity, specified in any form accepted by `EntityUidJson`
    parents: Vec<EntityUidJson>,
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, CedarValueJson>"))]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in tag values (including recursively)
    tags: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
}

/// Struct used to parse entities from JSON.
#[derive(Debug, Clone)]
pub struct EntityJsonParser<'e, 's, S = NoEntitiesSchema> {
    /// See comments on [`EntityJsonParser::new()`] for the interpretation and
    /// effects of this `schema` field.
    ///
    /// (Long doc comment on `EntityJsonParser::new()` is not repeated here, and
    /// instead incorporated by reference, to avoid them becoming out of sync.)
    schema: Option<&'s S>,

    /// Extensions which are active for the JSON parsing.
    extensions: &'e Extensions<'e>,

    /// Whether to compute, enforce, or assume TC for entities parsed using this
    /// parser.
    tc_computation: TCComputation,
}

/// Schema information about a single entity can take one of these forms:
#[derive(Debug)]
enum EntitySchemaInfo<E> {
    /// There is no schema, i.e. we're not doing schema-based parsing. We don't
    /// have attribute type information in the schema for action entities, so
    /// these are also parsed without schema-based parsing.
    NoSchema,
    /// The entity is a non-action, and here's the schema's information
    /// about its type
    NonAction(E),
}

impl<'e, 's, S> EntityJsonParser<'e, 's, S> {
    /// Create a new `EntityJsonParser`.
    ///
    /// `schema` represents a source of `Action` entities, which will be added
    /// to the entities parsed from JSON.
    /// (If any `Action` entities are present in the JSON, and a `schema` is
    /// also provided, each `Action` entity in the JSON must exactly match its
    /// definition in the schema or an error is returned.)
    ///
    /// If a `schema` is present, this will also inform the parsing: for
    /// instance, it will allow `__entity` and `__extn` escapes to be implicit.
    ///
    /// Finally, if a `schema` is present, the `EntityJsonParser` will ensure
    /// that the produced entities fully conform to the `schema` -- for
    /// instance, it will error if attributes have the wrong types (e.g., string
    /// instead of integer), or if required attributes are missing or
    /// superfluous attributes are provided.
    ///
    /// If you pass `TCComputation::AssumeAlreadyComputed`, then the caller is
    /// responsible for ensuring that TC holds before calling this method.
    pub fn new(
        schema: Option<&'s S>,
        extensions: &'e Extensions<'e>,
        tc_computation: TCComputation,
    ) -> Self {
        Self {
            schema,
            extensions,
            tc_computation,
        }
    }
}

impl<S: Schema> EntityJsonParser<'_, '_, S> {
    /// Parse an entities JSON file (in [`&str`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_str(&self, json: &str) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_value(&self, json: serde_json::Value) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an [`Entities`] object.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn from_json_file(&self, json: impl std::io::Read) -> Result<Entities, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.parse_ejsons(ejsons)
    }

    /// Parse an entities JSON file (in [`&str`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_str(
        &self,
        json: &str,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_str(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// Parse an entities JSON file (in [`serde_json::Value`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_value(
        &self,
        json: serde_json::Value,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_value(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// Parse an entities JSON file (in [`std::io::Read`] form) into an iterator over [`Entity`]s.
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`.
    pub fn iter_from_json_file(
        &self,
        json: impl std::io::Read,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let ejsons: Vec<EntityJson> =
            serde_json::from_reader(json).map_err(JsonDeserializationError::from)?;
        self.iter_ejson_to_iter_entity(ejsons)
    }

    /// Internal function that converts an iterator over [`EntityJson`] into an
    /// iterator over [`Entity`] and also adds any `Action` entities declared in
    /// `self.schema`.
    fn iter_ejson_to_iter_entity(
        &self,
        ejsons: impl IntoIterator<Item = EntityJson>,
    ) -> Result<impl Iterator<Item = Entity> + '_, EntitiesError> {
        let mut entities: Vec<Entity> = ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson).map_err(EntitiesError::from))
            .collect::<Result<_, _>>()?;
        if let Some(schema) = &self.schema {
            entities.extend(
                schema
                    .action_entities()
                    .into_iter()
                    .map(Arc::unwrap_or_clone),
            );
        }
        Ok(entities.into_iter())
    }

    /// Parse a single entity from an in-memory JSON value
    pub fn single_from_json_value(
        &self,
        value: serde_json::Value,
    ) -> Result<Entity, EntitiesError> {
        let ejson = serde_json::from_value(value).map_err(JsonDeserializationError::from)?;
        self.single_from_ejson(ejson)
    }

    /// Parse a single entity from a JSON string
    pub fn single_from_json_str(&self, src: impl AsRef<str>) -> Result<Entity, EntitiesError> {
        let ejson = serde_json::from_str(src.as_ref()).map_err(JsonDeserializationError::from)?;
        self.single_from_ejson(ejson)
    }

    /// Parse a single entity from a JSON reader
    pub fn single_from_json_file(&self, r: impl Read) -> Result<Entity, EntitiesError> {
        let ejson = serde_json::from_reader(r).map_err(JsonDeserializationError::from)?;
        self.single_from_ejson(ejson)
    }

    fn single_from_ejson(&self, ejson: EntityJson) -> Result<Entity, EntitiesError> {
        let entity = self.parse_ejson(ejson)?;
        match self.schema {
            None => Ok(entity),
            Some(schema) => {
                let checker = EntitySchemaConformanceChecker::new(schema, self.extensions);
                checker.validate_entity(&entity)?;
                Ok(entity)
            }
        }
    }

    /// Internal function that creates an [`Entities`] from a stream of [`EntityJson`].
    ///
    /// If the `EntityJsonParser` has a `schema`, this also adds `Action`
    /// entities declared in the `schema`, and validates all the entities
    /// against the schema.
    fn parse_ejsons(
        &self,
        ejsons: impl IntoIterator<Item = EntityJson>,
    ) -> Result<Entities, EntitiesError> {
        let entities: Vec<Entity> = ejsons
            .into_iter()
            .map(|ejson| self.parse_ejson(ejson))
            .collect::<Result<_, _>>()?;
        Entities::from_entities(entities, self.schema, self.tc_computation, self.extensions)
    }

    /// Internal function that parses an `EntityJson` into an `Entity`.
    ///
    /// This function is not responsible for fully validating the `Entity`
    /// against the `schema`; that happens on construction of an `Entities`
    fn parse_ejson(&self, ejson: EntityJson) -> Result<Entity, JsonDeserializationError> {
        let uid = ejson
            .uid
            .into_euid(|| JsonDeserializationErrorContext::EntityUid)?;
        let etype = uid.entity_type();
        let entity_schema_info = match &self.schema {
            None => EntitySchemaInfo::NoSchema,
            Some(schema) => {
                if etype.is_action() {
                    // Action entities do not have attribute type information in the schema.
                    EntitySchemaInfo::NoSchema
                } else {
                    EntitySchemaInfo::NonAction(schema.entity_type(etype).ok_or_else(|| {
                        let suggested_types = schema
                            .entity_types_with_basename(&etype.name().basename())
                            .collect();
                        JsonDeserializationError::EntitySchemaConformance(
                            UnexpectedEntityTypeError {
                                uid: uid.clone(),
                                suggested_types,
                            }
                            .into(),
                        )
                    })?)
                }
            }
        };
        let vparser = ValueParser::new(self.extensions);
        let attrs: HashMap<SmolStr, RestrictedExpr> = ejson
            .attrs
            .into_iter()
            .map(|(k, v)| match &entity_schema_info {
                EntitySchemaInfo::NoSchema => Ok((
                    k.clone(),
                    vparser.val_into_restricted_expr(v.into(), None, || {
                        JsonDeserializationErrorContext::EntityAttribute {
                            uid: uid.clone(),
                            attr: k.clone(),
                        }
                    })?,
                )),
                EntitySchemaInfo::NonAction(desc) => {
                    // Depending on the expected type, we may parse the contents
                    // of the attribute differently.
                    let rexpr = match desc.attr_type(&k) {
                        // `None` indicates the attribute shouldn't exist -- see
                        // docs on the `attr_type()` trait method
                        None => {
                            if desc.open_attributes() {
                                vparser.val_into_restricted_expr(v.into(), None, || {
                                    JsonDeserializationErrorContext::EntityAttribute {
                                        uid: uid.clone(),
                                        attr: k.clone(),
                                    }
                                })?
                            } else {
                                return Err(JsonDeserializationError::EntitySchemaConformance(
                                    EntitySchemaConformanceError::unexpected_entity_attr(
                                        uid.clone(),
                                        k,
                                    ),
                                ));
                            }
                        }
                        Some(expected_ty) => vparser.val_into_restricted_expr(
                            v.into(),
                            Some(&expected_ty),
                            || JsonDeserializationErrorContext::EntityAttribute {
                                uid: uid.clone(),
                                attr: k.clone(),
                            },
                        )?,
                    };
                    Ok((k, rexpr))
                }
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        let tags: HashMap<SmolStr, RestrictedExpr> = ejson
            .tags
            .into_iter()
            .map(|(k, v)| match &entity_schema_info {
                EntitySchemaInfo::NoSchema => Ok((
                    k.clone(),
                    vparser.val_into_restricted_expr(v.into(), None, || {
                        JsonDeserializationErrorContext::EntityTag {
                            uid: uid.clone(),
                            tag: k.clone(),
                        }
                    })?,
                )),
                EntitySchemaInfo::NonAction(desc) => {
                    // Depending on the expected type, we may parse the contents
                    // of the tag differently.
                    let rexpr = match desc.tag_type() {
                        // `None` indicates no tags should exist -- see docs on
                        // the `tag_type()` trait method
                        None => {
                            return Err(JsonDeserializationError::EntitySchemaConformance(
                                EntitySchemaConformanceError::unexpected_entity_tag(uid.clone(), k),
                            ));
                        }
                        Some(expected_ty) => vparser.val_into_restricted_expr(
                            v.into(),
                            Some(&expected_ty),
                            || JsonDeserializationErrorContext::EntityTag {
                                uid: uid.clone(),
                                tag: k.clone(),
                            },
                        )?,
                    };
                    Ok((k, rexpr))
                }
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        let is_parent_allowed = |parent_euid: &EntityUID| {
            // full validation isn't done in this function (see doc comments on
            // this function), but we do need to do the following check which
            // happens even when there is no schema
            if etype.is_action() {
                if parent_euid.is_action() {
                    Ok(())
                } else {
                    Err(JsonDeserializationError::action_parent_is_not_action(
                        uid.clone(),
                        parent_euid.clone(),
                    ))
                }
            } else {
                Ok(()) // all parents are allowed
            }
        };
        let parents = ejson
            .parents
            .into_iter()
            .map(|parent| {
                parent.into_euid(|| JsonDeserializationErrorContext::EntityParents {
                    uid: uid.clone(),
                })
            })
            .map(|res| {
                res.and_then(|parent_euid| {
                    is_parent_allowed(&parent_euid)?;
                    Ok(parent_euid)
                })
            })
            .collect::<Result<_, JsonDeserializationError>>()?;
        Ok(Entity::new(
            uid,
            attrs,
            HashSet::new(),
            parents,
            tags,
            self.extensions,
        )?)
    }
}

impl EntityJson {
    /// Convert an `Entity` into an `EntityJson`
    ///
    /// (for the reverse transformation, use `EntityJsonParser`)
    pub fn from_entity(entity: &Entity) -> Result<Self, JsonSerializationError> {
        let serialize_kpvalue = |(k, pvalue): (&SmolStr, &PartialValue)| -> Result<_, _> {
            match pvalue {
                PartialValue::Value(value) => {
                    let cedarvaluejson = CedarValueJson::from_value(value.clone())?;
                    Ok((k.clone(), serde_json::to_value(cedarvaluejson)?.into()))
                }
                PartialValue::Residual(expr) => match BorrowedRestrictedExpr::new(expr) {
                    Ok(expr) => {
                        let cedarvaluejson = CedarValueJson::from_expr(expr)?;
                        Ok((k.clone(), serde_json::to_value(cedarvaluejson)?.into()))
                    }
                    Err(_) => Err(JsonSerializationError::residual(expr.clone())),
                },
            }
        };
        Ok(Self {
            // for now, we encode `uid` and `parents` using an implied `__entity` escape
            uid: EntityUidJson::ImplicitEntityEscape(TypeAndId::from(entity.uid())),
            attrs: entity
                .attrs()
                .map(serialize_kpvalue)
                .collect::<Result<_, JsonSerializationError>>()?,
            parents: entity
                .ancestors()
                .map(|euid| EntityUidJson::ImplicitEntityEscape(TypeAndId::from(euid.clone())))
                .collect(),
            tags: entity
                .tags()
                .map(serialize_kpvalue)
                .collect::<Result<_, JsonSerializationError>>()?,
        })
    }
}

// PANIC SAFETY unit test code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn reject_inconsistent_duplicates() {
        let json = serde_json::json!([
            {
                "uid" : {
                    "type" : "User",
                    "id" : "alice"
                },
                "attrs" : {},
                "parents": []
            },
            {
                "uid" : {
                    "type" : "User",
                    "id" : "alice"
                },
                "attrs" : {"location": "Greenland"},
                "parents": []
            }
        ]);
        let eparser: EntityJsonParser<'_, '_, NoEntitiesSchema> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        let e = eparser.from_json_value(json);
        let bad_euid: EntityUID = r#"User::"alice""#.parse().unwrap();
        assert_matches!(e, Err(EntitiesError::Duplicate(euid)) => {
          assert_eq!(&bad_euid, euid.euid(), r#"Returned euid should be User::"alice""#);
        });
    }

    #[test]
    fn simple() {
        let test = serde_json::json!({
            "uid" : { "type" : "A", "id" : "b" },
            "attrs" : {},
            "parents" : []
        });
        let x: Result<EntityJson, _> = serde_json::from_value(test);
        x.unwrap();
    }
}
