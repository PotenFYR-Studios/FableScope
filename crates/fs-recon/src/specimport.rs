//! API spec import (Phase 2, Web/API): parse OpenAPI/Swagger documents and
//! GraphQL SDL / introspection into a normalized endpoint + parameter inventory
//! that feeds API checklist coverage, param recon, and schema-aware fuzzing.
//!
//! Pure, deterministic, offline parsing over `serde_json::Value`. No network.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where a parameter lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    Query,
    Path,
    Header,
    Cookie,
    Body,
    GraphqlArg,
}

/// A normalized API parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiParam {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub type_hint: Option<String>,
}

/// A normalized API endpoint/operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub path: String,
    pub method: String,
    pub operation_id: Option<String>,
    pub params: Vec<ApiParam>,
}

/// The normalized inventory produced by importing a spec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiInventory {
    pub source: String, // "openapi" | "swagger" | "graphql"
    pub title: Option<String>,
    pub version: Option<String>,
    pub base_paths: Vec<String>,
    pub endpoints: Vec<ApiEndpoint>,
}

impl ApiInventory {
    /// Distinct parameter names across the inventory (for param-recon seeding).
    pub fn param_names(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = BTreeSet::new();
        for e in &self.endpoints {
            for p in &e.params {
                set.insert(p.name.clone());
            }
        }
        set.into_iter().collect()
    }
}

fn type_of(schema: Option<&serde_json::Value>) -> Option<String> {
    schema?.get("type").and_then(|v| v.as_str()).map(String::from)
}

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

/// Parse an OpenAPI 3.x or Swagger 2.0 document (as JSON).
pub fn parse_openapi(doc: &serde_json::Value) -> ApiInventory {
    let is_v2 = doc.get("swagger").is_some();
    let mut inv = ApiInventory {
        source: if is_v2 { "swagger".into() } else { "openapi".into() },
        title: doc.get("info").and_then(|i| i.get("title")).and_then(|v| v.as_str()).map(String::from),
        version: doc.get("info").and_then(|i| i.get("version")).and_then(|v| v.as_str()).map(String::from),
        base_paths: vec![],
        endpoints: vec![],
    };
    // Base path: OpenAPI servers[].url or Swagger basePath.
    if let Some(servers) = doc.get("servers").and_then(|v| v.as_array()) {
        for s in servers {
            if let Some(u) = s.get("url").and_then(|v| v.as_str()) {
                inv.base_paths.push(u.to_string());
            }
        }
    } else if let Some(bp) = doc.get("basePath").and_then(|v| v.as_str()) {
        inv.base_paths.push(bp.to_string());
    }

    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return inv;
    };
    for (path, item) in paths {
        // Path-level shared parameters.
        let shared = item.get("parameters").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        for method in METHODS {
            let Some(op) = item.get(method) else { continue };
            let mut params: Vec<ApiParam> = Vec::new();
            // Merge path-level + operation-level parameters.
            let mut raw_params = shared.clone();
            if let Some(ps) = op.get("parameters").and_then(|v| v.as_array()) {
                raw_params.extend(ps.iter().cloned());
            }
            for p in &raw_params {
                let Some(name) = p.get("name").and_then(|v| v.as_str()) else { continue };
                let location = match p.get("in").and_then(|v| v.as_str()) {
                    Some("query") => ParamLocation::Query,
                    Some("path") => ParamLocation::Path,
                    Some("header") => ParamLocation::Header,
                    Some("cookie") => ParamLocation::Cookie,
                    Some("body") | Some("formData") => ParamLocation::Body,
                    _ => ParamLocation::Query,
                };
                let type_hint = type_of(p.get("schema")).or_else(|| p.get("type").and_then(|v| v.as_str()).map(String::from));
                params.push(ApiParam {
                    name: name.to_string(),
                    location,
                    required: p.get("required").and_then(|v| v.as_bool()).unwrap_or(false),
                    type_hint,
                });
            }
            // OpenAPI 3 requestBody JSON schema property names -> body params.
            if let Some(props) = op
                .get("requestBody")
                .and_then(|b| b.get("content"))
                .and_then(|c| c.get("application/json"))
                .and_then(|j| j.get("schema"))
                .and_then(|s| s.get("properties"))
                .and_then(|v| v.as_object())
            {
                let required: BTreeSet<String> = op
                    .get("requestBody")
                    .and_then(|b| b.get("content"))
                    .and_then(|c| c.get("application/json"))
                    .and_then(|j| j.get("schema"))
                    .and_then(|s| s.get("required"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                for (pname, pschema) in props {
                    params.push(ApiParam {
                        name: pname.clone(),
                        location: ParamLocation::Body,
                        required: required.contains(pname),
                        type_hint: type_of(Some(pschema)),
                    });
                }
            }
            inv.endpoints.push(ApiEndpoint {
                path: path.clone(),
                method: method.to_uppercase(),
                operation_id: op.get("operationId").and_then(|v| v.as_str()).map(String::from),
                params,
            });
        }
    }
    inv.endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    inv
}

/// Parse GraphQL SDL (schema definition language) into query/mutation
/// operations with their argument names. Lightweight: extracts fields and their
/// `(arg: Type)` argument lists from the `type Query`/`type Mutation` blocks.
pub fn parse_graphql_sdl(sdl: &str) -> ApiInventory {
    let mut inv = ApiInventory { source: "graphql".into(), ..Default::default() };
    for root in ["Query", "Mutation"] {
        let Some(block) = extract_type_block(sdl, root) else { continue };
        for (field, args) in parse_fields(&block) {
            let params: Vec<ApiParam> = args
                .into_iter()
                .map(|(name, ty, required)| ApiParam {
                    name,
                    location: ParamLocation::GraphqlArg,
                    required,
                    type_hint: Some(ty),
                })
                .collect();
            inv.endpoints.push(ApiEndpoint {
                path: format!("/graphql#{}", field),
                method: root.to_uppercase(),
                operation_id: Some(field),
                params,
            });
        }
    }
    inv.endpoints.sort_by(|a, b| a.path.cmp(&b.path));
    inv
}

fn extract_type_block(sdl: &str, type_name: &str) -> Option<String> {
    let needle = format!("type {type_name}");
    let start = sdl.find(&needle)?;
    let brace = sdl[start..].find('{')? + start;
    let mut depth = 0;
    for (i, c) in sdl[brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(sdl[brace + 1..brace + i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_fields(block: &str) -> Vec<(String, Vec<(String, String, bool)>)> {
    let mut out = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // field(arg: Type!, arg2: Type): ReturnType
        let name_end = line.find(['(', ':']).unwrap_or(line.len());
        let field = line[..name_end].trim().to_string();
        if field.is_empty() {
            continue;
        }
        let mut args = Vec::new();
        if let (Some(o), Some(c)) = (line.find('('), line.find(')')) {
            if o < c {
                for a in line[o + 1..c].split(',') {
                    let a = a.trim();
                    if let Some((n, t)) = a.split_once(':') {
                        let t = t.trim();
                        args.push((n.trim().to_string(), t.trim_end_matches('!').to_string(), t.ends_with('!')));
                    }
                }
            }
        }
        out.push((field, args));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi3_endpoints_and_params() {
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "info": {"title": "Acme API", "version": "1.0"},
            "servers": [{"url": "https://api.acme.com/v1"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
                            {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
                        ]
                    },
                    "post": {
                        "requestBody": {"content": {"application/json": {"schema": {
                            "type": "object", "required": ["email"],
                            "properties": {"email": {"type": "string"}, "name": {"type": "string"}}
                        }}}}
                    }
                }
            }
        });
        let inv = parse_openapi(&doc);
        assert_eq!(inv.source, "openapi");
        assert_eq!(inv.title.as_deref(), Some("Acme API"));
        assert_eq!(inv.base_paths, vec!["https://api.acme.com/v1"]);
        assert_eq!(inv.endpoints.len(), 2);
        let get = inv.endpoints.iter().find(|e| e.method == "GET").unwrap();
        assert!(get.params.iter().any(|p| p.name == "id" && p.location == ParamLocation::Path && p.required));
        let post = inv.endpoints.iter().find(|e| e.method == "POST").unwrap();
        assert!(post.params.iter().any(|p| p.name == "email" && p.location == ParamLocation::Body && p.required));
        assert!(inv.param_names().contains(&"email".to_string()));
    }

    #[test]
    fn swagger2_basepath_and_params() {
        let doc = serde_json::json!({
            "swagger": "2.0",
            "basePath": "/api",
            "paths": {"/search": {"get": {"parameters": [{"name": "q", "in": "query", "type": "string", "required": true}]}}}
        });
        let inv = parse_openapi(&doc);
        assert_eq!(inv.source, "swagger");
        assert_eq!(inv.base_paths, vec!["/api"]);
        assert!(inv.endpoints[0].params.iter().any(|p| p.name == "q" && p.required));
    }

    #[test]
    fn graphql_sdl_queries_and_args() {
        let sdl = r#"
            type Query {
              user(id: ID!): User
              search(term: String, limit: Int): [User]
            }
            type Mutation {
              createUser(email: String!): User
            }
        "#;
        let inv = parse_graphql_sdl(sdl);
        assert_eq!(inv.source, "graphql");
        let user = inv.endpoints.iter().find(|e| e.operation_id.as_deref() == Some("user")).unwrap();
        assert!(user.params.iter().any(|p| p.name == "id" && p.required && p.location == ParamLocation::GraphqlArg));
        let create = inv.endpoints.iter().find(|e| e.operation_id.as_deref() == Some("createUser")).unwrap();
        assert_eq!(create.method, "MUTATION");
        assert!(create.params.iter().any(|p| p.name == "email" && p.required));
        assert!(inv.param_names().contains(&"term".to_string()));
    }
}
