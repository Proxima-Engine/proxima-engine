use mongodb::bson::{self, Bson, Document};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Mutex,
};
use uuid::Uuid;

const RESERVED_TENANT_FIELD: &str = "_proxima_tenant_id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MongoPolicyError {
    InvalidTenant,
    InvalidDatabase,
    MissingDatabase,
    WrongDatabase,
    MissingCommand,
    UnsupportedCommand(String),
    InvalidCommand(String),
    UnsafeOperator(String),
    UnsafePipelineStage(String),
    CrossDatabaseStage,
    CrossTenantSession,
    UnknownSession,
    CrossTenantCursor,
    UnknownCursor,
    CursorCollision,
    RegistryUnavailable,
}

impl std::fmt::Display for MongoPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenant => write!(f, "invalid MongoDB tenant identifier"),
            Self::InvalidDatabase => write!(f, "invalid MongoDB database name"),
            Self::MissingDatabase => write!(f, "MongoDB command is missing $db"),
            Self::WrongDatabase => write!(f, "MongoDB command targets a database outside the authenticated tenant"),
            Self::MissingCommand => write!(f, "MongoDB command document is empty"),
            Self::UnsupportedCommand(name) => write!(f, "MongoDB command is not admitted: {name}"),
            Self::InvalidCommand(reason) => write!(f, "invalid MongoDB command: {reason}"),
            Self::UnsafeOperator(name) => write!(f, "MongoDB operator is not admitted: {name}"),
            Self::UnsafePipelineStage(name) => write!(f, "MongoDB aggregation stage is not admitted: {name}"),
            Self::CrossDatabaseStage => write!(f, "cross-database aggregation references are denied"),
            Self::CrossTenantSession => write!(f, "MongoDB session belongs to another tenant"),
            Self::UnknownSession => write!(f, "MongoDB session is not registered"),
            Self::CrossTenantCursor => write!(f, "MongoDB cursor belongs to another tenant or namespace"),
            Self::UnknownCursor => write!(f, "MongoDB cursor is not registered"),
            Self::CursorCollision => write!(f, "could not allocate a unique MongoDB cursor identifier"),
            Self::RegistryUnavailable => write!(f, "MongoDB session or cursor registry is unavailable"),
        }
    }
}

impl std::error::Error for MongoPolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MongoCommandKind {
    Find,
    Aggregate,
    Insert,
    Update,
    Delete,
    Count,
    Distinct,
    FindAndModify,
    GetMore,
    KillCursors,
    ListCollections,
    ListIndexes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoTenantPolicy {
    tenant_id: String,
    database: String,
}

impl MongoTenantPolicy {
    pub fn new(tenant_id: impl Into<String>, database: impl Into<String>) -> Result<Self, MongoPolicyError> {
        let tenant_id = tenant_id.into();
        let database = database.into();
        if tenant_id.is_empty()
            || tenant_id.len() > 128
            || !tenant_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(MongoPolicyError::InvalidTenant);
        }
        if !valid_database_name(&database) {
            return Err(MongoPolicyError::InvalidDatabase);
        }
        Ok(Self { tenant_id, database })
    }

    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn database(&self) -> &str { &self.database }

    /// Admits a deliberately small, fail-closed command surface. Each command
    /// must target the principal's one assigned database. Cross-database
    /// aggregation and server-administration commands are never forwarded.
    pub fn authorize(&self, command: &Document) -> Result<MongoCommandKind, MongoPolicyError> {
        let (name, value) = command.iter().next().ok_or(MongoPolicyError::MissingCommand)?;
        let database = command.get_str("$db").map_err(|_| MongoPolicyError::MissingDatabase)?;
        if database != self.database {
            return Err(MongoPolicyError::WrongDatabase);
        }

        match name.as_str() {
            "find" => {
                validate_collection(value, name)?;
                validate_optional_query(command, "filter")?;
                Ok(MongoCommandKind::Find)
            }
            "aggregate" => {
                validate_collection(value, name)?;
                let pipeline = command.get_array("pipeline")
                    .map_err(|_| MongoPolicyError::InvalidCommand("aggregate.pipeline must be an array".into()))?;
                validate_pipeline(pipeline, &self.database)?;
                Ok(MongoCommandKind::Aggregate)
            }
            "insert" => {
                validate_collection(value, name)?;
                let documents = command.get_array("documents")
                    .map_err(|_| MongoPolicyError::InvalidCommand("insert.documents must be an array".into()))?;
                if documents.is_empty() {
                    return Err(MongoPolicyError::InvalidCommand("insert.documents cannot be empty".into()));
                }
                for document in documents {
                    let document = document.as_document()
                        .ok_or_else(|| MongoPolicyError::InvalidCommand("insert document must be a BSON document".into()))?;
                    validate_query_document(document)?;
                    if document.contains_key(RESERVED_TENANT_FIELD) {
                        return Err(MongoPolicyError::InvalidCommand("reserved tenant metadata cannot be supplied by clients".into()));
                    }
                }
                Ok(MongoCommandKind::Insert)
            }
            "update" => {
                validate_collection(value, name)?;
                let updates = command.get_array("updates")
                    .map_err(|_| MongoPolicyError::InvalidCommand("update.updates must be an array".into()))?;
                for update in updates {
                    let update = update.as_document()
                        .ok_or_else(|| MongoPolicyError::InvalidCommand("update entry must be a document".into()))?;
                    let filter = update.get_document("q")
                        .map_err(|_| MongoPolicyError::InvalidCommand("update entry is missing q document".into()))?;
                    validate_query_document(filter)?;
                    if update.get_bool("upsert").unwrap_or(false) {
                        return Err(MongoPolicyError::InvalidCommand("upsert is denied until tenant-safe upsert semantics are enabled".into()));
                    }
                    validate_update_value(update.get("u").ok_or_else(|| MongoPolicyError::InvalidCommand("update entry is missing u".into()))?, &self.database)?;
                }
                Ok(MongoCommandKind::Update)
            }
            "delete" => {
                validate_collection(value, name)?;
                let deletes = command.get_array("deletes")
                    .map_err(|_| MongoPolicyError::InvalidCommand("delete.deletes must be an array".into()))?;
                for delete in deletes {
                    let delete = delete.as_document()
                        .ok_or_else(|| MongoPolicyError::InvalidCommand("delete entry must be a document".into()))?;
                    validate_query_document(delete.get_document("q")
                        .map_err(|_| MongoPolicyError::InvalidCommand("delete entry is missing q document".into()))?)?;
                }
                Ok(MongoCommandKind::Delete)
            }
            "count" | "distinct" => {
                validate_collection(value, name)?;
                validate_optional_query(command, "query")?;
                if name == "count" { Ok(MongoCommandKind::Count) } else { Ok(MongoCommandKind::Distinct) }
            }
            "findAndModify" => {
                validate_collection(value, name)?;
                if let Ok(query) = command.get_document("query") { validate_query_document(query)?; }
                if command.get_bool("upsert").unwrap_or(false) {
                    return Err(MongoPolicyError::InvalidCommand("findAndModify upsert is denied".into()));
                }
                if let Some(update) = command.get("update") { validate_update_value(update, &self.database)?; }
                Ok(MongoCommandKind::FindAndModify)
            }
            "getMore" => {
                validate_collection(command.get("collection").ok_or_else(|| MongoPolicyError::InvalidCommand("getMore.collection is required".into()))?, "getMore")?;
                if command.get_i64("getMore").is_err() {
                    return Err(MongoPolicyError::InvalidCommand("getMore requires an int64 cursor id".into()));
                }
                Ok(MongoCommandKind::GetMore)
            }
            "killCursors" => {
                validate_collection(value, name)?;
                let cursors = command.get_array("cursors")
                    .map_err(|_| MongoPolicyError::InvalidCommand("killCursors.cursors must be an array".into()))?;
                if cursors.iter().any(|cursor| cursor.as_i64().is_none()) {
                    return Err(MongoPolicyError::InvalidCommand("killCursors cursor ids must be int64".into()));
                }
                Ok(MongoCommandKind::KillCursors)
            }
            "listCollections" => Ok(MongoCommandKind::ListCollections),
            "listIndexes" => {
                validate_collection(value, name)?;
                Ok(MongoCommandKind::ListIndexes)
            }
            other => Err(MongoPolicyError::UnsupportedCommand(other.to_owned())),
        }
    }

    /// Optional defense-in-depth for schemas that reserve a tenant metadata
    /// field. Existing databases must be migrated before enabling this mode.
    pub fn stamp_insert_document(&self, document: &mut Document) -> Result<(), MongoPolicyError> {
        if document.contains_key(RESERVED_TENANT_FIELD) {
            return Err(MongoPolicyError::InvalidCommand("reserved tenant metadata cannot be supplied by clients".into()));
        }
        document.insert(RESERVED_TENANT_FIELD, self.tenant_id.clone());
        Ok(())
    }

    pub fn tenant_filter(&self) -> Document {
        bson::doc! { RESERVED_TENANT_FIELD: &self.tenant_id }
    }
}

fn valid_database_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.chars().any(|c| matches!(c, '/' | '\\' | '.' | ' ' | '"' | '$' | '\0'))
        && value != "admin"
        && value != "local"
        && value != "config"
}

fn validate_collection(value: &Bson, command: &str) -> Result<(), MongoPolicyError> {
    let name = value.as_str().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{command} must name a collection")))?;
    if name.is_empty() || name.len() > 120 || name.starts_with("system.") || name.contains('$') || name.contains('\0') {
        return Err(MongoPolicyError::InvalidCommand(format!("{command} uses a reserved or invalid collection name")));
    }
    Ok(())
}

fn validate_optional_query(command: &Document, field: &str) -> Result<(), MongoPolicyError> {
    if let Some(value) = command.get(field) {
        let document = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{field} must be a BSON document")))?;
        validate_query_document(document)?;
    }
    Ok(())
}

fn validate_query_document(document: &Document) -> Result<(), MongoPolicyError> {
    for (key, value) in document {
        if matches!(key.as_str(), "$where" | "$function" | "$accumulator" | "$out" | "$merge" | "$changeStream" | "$currentOp" | "$listSessions" | "$listLocalSessions") {
            return Err(MongoPolicyError::UnsafeOperator(key.clone()));
        }
        validate_nested_value(value)?;
    }
    Ok(())
}

fn validate_nested_value(value: &Bson) -> Result<(), MongoPolicyError> {
    match value {
        Bson::Document(document) => validate_query_document(document),
        Bson::Array(values) => {
            for value in values { validate_nested_value(value)?; }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_update_value(value: &Bson, tenant_database: &str) -> Result<(), MongoPolicyError> {
    match value {
        Bson::Document(document) => {
            for (operator, payload) in document {
                if operator == RESERVED_TENANT_FIELD || operator.ends_with(&format!(".{RESERVED_TENANT_FIELD}")) {
                    return Err(MongoPolicyError::InvalidCommand("updates cannot modify reserved tenant metadata".into()));
                }
                if matches!(operator.as_str(), "$where" | "$function" | "$accumulator" | "$rename") {
                    return Err(MongoPolicyError::UnsafeOperator(operator.clone()));
                }
                if let Bson::Document(fields) = payload {
                    if fields.keys().any(|field| field == RESERVED_TENANT_FIELD || field.ends_with(&format!(".{RESERVED_TENANT_FIELD}"))) {
                        return Err(MongoPolicyError::InvalidCommand("updates cannot modify reserved tenant metadata".into()));
                    }
                }
                validate_nested_value(payload)?;
            }
            Ok(())
        }
        Bson::Array(pipeline) => validate_pipeline(pipeline, tenant_database),
        _ => Err(MongoPolicyError::InvalidCommand("update.u must be a document or aggregation pipeline".into())),
    }
}

fn validate_pipeline(pipeline: &[Bson], tenant_database: &str) -> Result<(), MongoPolicyError> {
    for stage in pipeline {
        let stage = stage.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation stages must be documents".into()))?;
        if stage.len() != 1 {
            return Err(MongoPolicyError::InvalidCommand("each aggregation stage must contain exactly one operator".into()));
        }
        let (name, value) = stage.iter().next().unwrap();
        match name.as_str() {
            "$match" | "$redact" => {
                let document = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{name} must contain a document")))?;
                validate_query_document(document)?;
            }
            "$project" | "$addFields" | "$set" | "$unset" | "$sort" | "$limit" | "$skip" | "$unwind"
            | "$replaceRoot" | "$replaceWith" | "$group" | "$count" | "$bucket" | "$bucketAuto"
            | "$sortByCount" | "$sample" | "$setWindowFields" | "$densify" | "$fill" => {
                validate_nested_value(value)?;
            }
            "$facet" => {
                let facets = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$facet must contain named pipelines".into()))?;
                for pipeline in facets.values() {
                    let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$facet values must be arrays".into()))?;
                    validate_pipeline(pipeline, tenant_database)?;
                }
            }
            "$lookup" => {
                let lookup = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$lookup must be a document".into()))?;
                validate_foreign_namespace(lookup.get("from"), tenant_database)?;
                if let Some(pipeline) = lookup.get("pipeline") {
                    let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$lookup.pipeline must be an array".into()))?;
                    validate_pipeline(pipeline, tenant_database)?;
                }
            }
            "$unionWith" => {
                match value {
                    Bson::String(collection) => validate_collection(&Bson::String(collection.clone()), "$unionWith")?,
                    Bson::Document(union) => {
                        validate_foreign_namespace(union.get("coll").or_else(|| union.get("from")), tenant_database)?;
                        if let Some(pipeline) = union.get("pipeline") {
                            let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$unionWith.pipeline must be an array".into()))?;
                            validate_pipeline(pipeline, tenant_database)?;
                        }
                    }
                    _ => return Err(MongoPolicyError::InvalidCommand("$unionWith must name a collection".into())),
                }
            }
            "$graphLookup" => {
                let graph = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$graphLookup must be a document".into()))?;
                validate_foreign_namespace(graph.get("from"), tenant_database)?;
            }
            "$geoNear" => {
                let geo = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$geoNear must be a document".into()))?;
                if let Some(query) = geo.get_document("query").ok() { validate_query_document(query)?; }
            }
            "$out" | "$merge" | "$changeStream" | "$currentOp" | "$indexStats" | "$collStats"
            | "$planCacheStats" | "$listSessions" | "$listLocalSessions" | "$search" | "$vectorSearch"
            | "$documents" | "$function" | "$accumulator" => {
                return Err(MongoPolicyError::UnsafePipelineStage(name.clone()));
            }
            other => return Err(MongoPolicyError::UnsafePipelineStage(other.to_owned())),
        }
    }
    Ok(())
}

fn validate_foreign_namespace(value: Option<&Bson>, tenant_database: &str) -> Result<(), MongoPolicyError> {
    let value = value.ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation foreign namespace is missing".into()))?;
    match value {
        Bson::String(collection) => validate_collection(&Bson::String(collection.clone()), "aggregation namespace"),
        Bson::Document(namespace) => {
            if namespace.get_str("db").is_ok_and(|db| db != tenant_database) {
                return Err(MongoPolicyError::CrossDatabaseStage);
            }
            let collection = namespace.get("coll").or_else(|| namespace.get("collection"));
            validate_collection(collection.ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation namespace is missing coll".into()))?, "aggregation namespace")
        }
        _ => Err(MongoPolicyError::InvalidCommand("aggregation namespace must be a collection or namespace document".into())),
    }
}

#[derive(Debug, Clone)]
struct CursorBinding {
    tenant_id: String,
    database: String,
    collection: String,
    upstream_cursor_id: i64,
}

pub struct MongoCursorRegistry {
    next_id: AtomicI64,
    cursors: Mutex<HashMap<i64, CursorBinding>>,
}

impl Default for MongoCursorRegistry {
    fn default() -> Self {
        let seed = (Uuid::new_v4().as_u128() as u64 & i64::MAX as u64).max(1) as i64;
        Self { next_id: AtomicI64::new(seed), cursors: Mutex::new(HashMap::new()) }
    }
}

impl MongoCursorRegistry {
    pub fn register(&self, tenant_id: &str, database: &str, collection: &str, upstream_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        for _ in 0..32 {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
            if let std::collections::hash_map::Entry::Vacant(entry) = cursors.entry(candidate) {
                entry.insert(CursorBinding { tenant_id: tenant_id.to_owned(), database: database.to_owned(), collection: collection.to_owned(), upstream_cursor_id });
                return Ok(candidate);
            }
        }
        Err(MongoPolicyError::CursorCollision)
    }

    pub fn resolve_get_more(&self, tenant_id: &str, database: &str, collection: &str, client_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let binding = cursors.get(&client_cursor_id).ok_or(MongoPolicyError::UnknownCursor)?;
        if binding.tenant_id != tenant_id || binding.database != database || binding.collection != collection {
            return Err(MongoPolicyError::CrossTenantCursor);
        }
        Ok(binding.upstream_cursor_id)
    }

    pub fn authorize_kill(&self, tenant_id: &str, database: &str, collection: &str, client_cursor_ids: &[i64]) -> Result<Vec<i64>, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let mut upstream_ids = Vec::with_capacity(client_cursor_ids.len());
        for id in client_cursor_ids {
            let binding = cursors.get(id).ok_or(MongoPolicyError::UnknownCursor)?;
            if binding.tenant_id != tenant_id || binding.database != database || binding.collection != collection {
                return Err(MongoPolicyError::CrossTenantCursor);
            }
            upstream_ids.push(binding.upstream_cursor_id);
        }
        for id in client_cursor_ids { cursors.remove(id); }
        Ok(upstream_ids)
    }

    pub fn release(&self, tenant_id: &str, client_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let binding = cursors.get(&client_cursor_id).ok_or(MongoPolicyError::UnknownCursor)?;
        if binding.tenant_id != tenant_id { return Err(MongoPolicyError::CrossTenantCursor); }
        Ok(cursors.remove(&client_cursor_id).expect("cursor was checked").upstream_cursor_id)
    }
}

#[derive(Default)]
pub struct MongoSessionRegistry {
    sessions: Mutex<HashMap<Vec<u8>, String>>,
}

impl MongoSessionRegistry {
    pub fn bind(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        let mut sessions = self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        match sessions.get(&key) {
            Some(owner) if owner != tenant_id => Err(MongoPolicyError::CrossTenantSession),
            Some(_) => Ok(()),
            None => { sessions.insert(key, tenant_id.to_owned()); Ok(()) }
        }
    }

    pub fn authorize(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        let sessions = self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        match sessions.get(&key) {
            Some(owner) if owner == tenant_id => Ok(()),
            Some(_) => Err(MongoPolicyError::CrossTenantSession),
            None => Err(MongoPolicyError::UnknownSession),
        }
    }

    pub fn release(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        self.authorize(tenant_id, lsid)?;
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    fn policy() -> MongoTenantPolicy {
        MongoTenantPolicy::new("tenant-a", "tenant_a_db").unwrap()
    }

    fn command(name: &str, value: Bson) -> Document {
        let mut command = Document::new();
        command.insert(name, value);
        command.insert("$db", "tenant_a_db");
        command
    }

    #[test]
    fn requires_exact_tenant_database() {
        let mut command = command("find", Bson::String("records".into()));
        command.insert("$db", "tenant_b_db");
        assert_eq!(policy().authorize(&command), Err(MongoPolicyError::WrongDatabase));
    }

    #[test]
    fn denies_admin_and_unknown_commands() {
        for name in ["listDatabases", "dropDatabase", "createUser", "mapReduce", "eval", "renameCollection"] {
            let command = command(name, Bson::Int32(1));
            assert!(matches!(policy().authorize(&command), Err(MongoPolicyError::UnsupportedCommand(_))));
        }
    }

    #[test]
    fn allows_scoped_find_and_rejects_javascript_predicates() {
        let mut safe = command("find", Bson::String("records".into()));
        safe.insert("filter", doc! { "status": "active" });
        assert_eq!(policy().authorize(&safe), Ok(MongoCommandKind::Find));

        let mut unsafe_query = command("find", Bson::String("records".into()));
        unsafe_query.insert("filter", doc! { "$where": "return true" });
        assert!(matches!(policy().authorize(&unsafe_query), Err(MongoPolicyError::UnsafeOperator(_))));
    }

    #[test]
    fn aggregate_allows_safe_pipeline_and_rejects_cross_database_lookup() {
        let mut safe = command("aggregate", Bson::String("records".into()));
        safe.insert("pipeline", vec![doc! { "$match": { "status": "active" } }, doc! { "$limit": 5 }]);
        assert_eq!(policy().authorize(&safe), Ok(MongoCommandKind::Aggregate));

        let mut cross_db = command("aggregate", Bson::String("records".into()));
        cross_db.insert("pipeline", vec![doc! { "$lookup": { "from": { "db": "tenant_b_db", "coll": "records" }, "pipeline": [], "as": "joined" } }]);
        assert_eq!(policy().authorize(&cross_db), Err(MongoPolicyError::CrossDatabaseStage));
    }

    #[test]
    fn aggregate_rejects_output_and_change_stream_stages() {
        for stage in [doc! { "$out": "exfiltration" }, doc! { "$merge": "exfiltration" }, doc! { "$changeStream": {} }] {
            let mut command = command("aggregate", Bson::String("records".into()));
            command.insert("pipeline", vec![stage]);
            assert!(matches!(policy().authorize(&command), Err(MongoPolicyError::UnsafePipelineStage(_))));
        }
    }

    #[test]
    fn update_upsert_and_reserved_tenant_field_mutations_are_denied() {
        let mut upsert = command("update", Bson::String("records".into()));
        upsert.insert("updates", vec![doc! { "q": {}, "u": { "$set": { "x": 1 } }, "upsert": true }]);
        assert!(matches!(policy().authorize(&upsert), Err(MongoPolicyError::InvalidCommand(_))));

        let mut reserved = command("update", Bson::String("records".into()));
        reserved.insert("updates", vec![doc! { "q": {}, "u": { "$set": { "_proxima_tenant_id": "tenant-b" } } }]);
        assert!(matches!(policy().authorize(&reserved), Err(MongoPolicyError::InvalidCommand(_))));
    }

    #[test]
    fn insert_metadata_is_stamped_by_policy_not_client() {
        let mut document = doc! { "value": "record" };
        policy().stamp_insert_document(&mut document).unwrap();
        assert_eq!(document.get_str(RESERVED_TENANT_FIELD).unwrap(), "tenant-a");

        let mut spoofed = Document::new();
        spoofed.insert(RESERVED_TENANT_FIELD, "tenant-b");
        assert!(policy().stamp_insert_document(&mut spoofed).is_err());
    }

    #[test]
    fn session_ids_are_bound_to_one_tenant() {
        let registry = MongoSessionRegistry::default();
        let lsid = doc! { "id": bson::Binary { subtype: bson::spec::BinarySubtype::Uuid, bytes: Uuid::new_v4().as_bytes().to_vec() } };
        registry.bind("tenant-a", &lsid).unwrap();
        registry.authorize("tenant-a", &lsid).unwrap();
        assert_eq!(registry.authorize("tenant-b", &lsid), Err(MongoPolicyError::CrossTenantSession));
        assert_eq!(registry.bind("tenant-b", &lsid), Err(MongoPolicyError::CrossTenantSession));
    }

    #[test]
    fn cursor_ids_are_opaque_and_tenant_bound() {
        let registry = MongoCursorRegistry::default();
        let client_id = registry.register("tenant-a", "tenant_a_db", "records", 991).unwrap();
        assert_ne!(client_id, 991);
        assert_eq!(registry.resolve_get_more("tenant-a", "tenant_a_db", "records", client_id).unwrap(), 991);
        assert_eq!(registry.resolve_get_more("tenant-b", "tenant_a_db", "records", client_id), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.release("tenant-b", client_id), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.release("tenant-a", client_id).unwrap(), 991);
    }

    #[test]
    fn kill_cursors_is_all_or_nothing_across_tenants() {
        let registry = MongoCursorRegistry::default();
        let a = registry.register("tenant-a", "tenant_a_db", "records", 1001).unwrap();
        let b = registry.register("tenant-b", "tenant_b_db", "records", 2002).unwrap();
        assert_eq!(registry.authorize_kill("tenant-a", "tenant_a_db", "records", &[a, b]), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.resolve_get_more("tenant-a", "tenant_a_db", "records", a).unwrap(), 1001);
        assert_eq!(registry.resolve_get_more("tenant-b", "tenant_b_db", "records", b).unwrap(), 2002);
        assert_eq!(registry.authorize_kill("tenant-a", "tenant_a_db", "records", &[a]).unwrap(), vec![1001]);
    }
}
 | '\0'))
        && value != "admin"
        && value != "local"
        && value != "config"
}

fn validate_collection(value: &Bson, command: &str) -> Result<(), MongoPolicyError> {
    let name = value.as_str().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{command} must name a collection")))?;
    if name.is_empty() || name.len() > 120 || name.starts_with("system.") || name.contains('$') || name.contains('\0') {
        return Err(MongoPolicyError::InvalidCommand(format!("{command} uses a reserved or invalid collection name")));
    }
    Ok(())
}

fn validate_optional_query(command: &Document, field: &str) -> Result<(), MongoPolicyError> {
    if let Some(value) = command.get(field) {
        let document = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{field} must be a BSON document")))?;
        validate_query_document(document)?;
    }
    Ok(())
}

fn validate_query_document(document: &Document) -> Result<(), MongoPolicyError> {
    for (key, value) in document {
        if matches!(key.as_str(), "$where" | "$function" | "$accumulator" | "$out" | "$merge" | "$changeStream" | "$currentOp" | "$listSessions" | "$listLocalSessions") {
            return Err(MongoPolicyError::UnsafeOperator(key.clone()));
        }
        validate_nested_value(value)?;
    }
    Ok(())
}

fn validate_nested_value(value: &Bson) -> Result<(), MongoPolicyError> {
    match value {
        Bson::Document(document) => validate_query_document(document),
        Bson::Array(values) => {
            for value in values { validate_nested_value(value)?; }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_update_value(value: &Bson, tenant_database: &str) -> Result<(), MongoPolicyError> {
    match value {
        Bson::Document(document) => {
            for (operator, payload) in document {
                if operator == RESERVED_TENANT_FIELD || operator.ends_with(&format!(".{RESERVED_TENANT_FIELD}")) {
                    return Err(MongoPolicyError::InvalidCommand("updates cannot modify reserved tenant metadata".into()));
                }
                if matches!(operator.as_str(), "$where" | "$function" | "$accumulator" | "$rename") {
                    return Err(MongoPolicyError::UnsafeOperator(operator.clone()));
                }
                if let Bson::Document(fields) = payload {
                    if fields.keys().any(|field| field == RESERVED_TENANT_FIELD || field.ends_with(&format!(".{RESERVED_TENANT_FIELD}"))) {
                        return Err(MongoPolicyError::InvalidCommand("updates cannot modify reserved tenant metadata".into()));
                    }
                }
                validate_nested_value(payload)?;
            }
            Ok(())
        }
        Bson::Array(pipeline) => validate_pipeline(pipeline, tenant_database),
        _ => Err(MongoPolicyError::InvalidCommand("update.u must be a document or aggregation pipeline".into())),
    }
}

fn validate_pipeline(pipeline: &[Bson], tenant_database: &str) -> Result<(), MongoPolicyError> {
    for stage in pipeline {
        let stage = stage.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation stages must be documents".into()))?;
        if stage.len() != 1 {
            return Err(MongoPolicyError::InvalidCommand("each aggregation stage must contain exactly one operator".into()));
        }
        let (name, value) = stage.iter().next().unwrap();
        match name.as_str() {
            "$match" | "$redact" => {
                let document = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand(format!("{name} must contain a document")))?;
                validate_query_document(document)?;
            }
            "$project" | "$addFields" | "$set" | "$unset" | "$sort" | "$limit" | "$skip" | "$unwind"
            | "$replaceRoot" | "$replaceWith" | "$group" | "$count" | "$bucket" | "$bucketAuto"
            | "$sortByCount" | "$sample" | "$setWindowFields" | "$densify" | "$fill" => {
                validate_nested_value(value)?;
            }
            "$facet" => {
                let facets = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$facet must contain named pipelines".into()))?;
                for pipeline in facets.values() {
                    let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$facet values must be arrays".into()))?;
                    validate_pipeline(pipeline, tenant_database)?;
                }
            }
            "$lookup" => {
                let lookup = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$lookup must be a document".into()))?;
                validate_foreign_namespace(lookup.get("from"), tenant_database)?;
                if let Some(pipeline) = lookup.get("pipeline") {
                    let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$lookup.pipeline must be an array".into()))?;
                    validate_pipeline(pipeline, tenant_database)?;
                }
            }
            "$unionWith" => {
                match value {
                    Bson::String(collection) => validate_collection(&Bson::String(collection.clone()), "$unionWith")?,
                    Bson::Document(union) => {
                        validate_foreign_namespace(union.get("coll").or_else(|| union.get("from")), tenant_database)?;
                        if let Some(pipeline) = union.get("pipeline") {
                            let pipeline = pipeline.as_array().ok_or_else(|| MongoPolicyError::InvalidCommand("$unionWith.pipeline must be an array".into()))?;
                            validate_pipeline(pipeline, tenant_database)?;
                        }
                    }
                    _ => return Err(MongoPolicyError::InvalidCommand("$unionWith must name a collection".into())),
                }
            }
            "$graphLookup" => {
                let graph = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$graphLookup must be a document".into()))?;
                validate_foreign_namespace(graph.get("from"), tenant_database)?;
            }
            "$geoNear" => {
                let geo = value.as_document().ok_or_else(|| MongoPolicyError::InvalidCommand("$geoNear must be a document".into()))?;
                if let Some(query) = geo.get_document("query").ok() { validate_query_document(query)?; }
            }
            "$out" | "$merge" | "$changeStream" | "$currentOp" | "$indexStats" | "$collStats"
            | "$planCacheStats" | "$listSessions" | "$listLocalSessions" | "$search" | "$vectorSearch"
            | "$documents" | "$function" | "$accumulator" => {
                return Err(MongoPolicyError::UnsafePipelineStage(name.clone()));
            }
            other => return Err(MongoPolicyError::UnsafePipelineStage(other.to_owned())),
        }
    }
    Ok(())
}

fn validate_foreign_namespace(value: Option<&Bson>, tenant_database: &str) -> Result<(), MongoPolicyError> {
    let value = value.ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation foreign namespace is missing".into()))?;
    match value {
        Bson::String(collection) => validate_collection(&Bson::String(collection.clone()), "aggregation namespace"),
        Bson::Document(namespace) => {
            if namespace.get_str("db").is_ok_and(|db| db != tenant_database) {
                return Err(MongoPolicyError::CrossDatabaseStage);
            }
            let collection = namespace.get("coll").or_else(|| namespace.get("collection"));
            validate_collection(collection.ok_or_else(|| MongoPolicyError::InvalidCommand("aggregation namespace is missing coll".into()))?, "aggregation namespace")
        }
        _ => Err(MongoPolicyError::InvalidCommand("aggregation namespace must be a collection or namespace document".into())),
    }
}

#[derive(Debug, Clone)]
struct CursorBinding {
    tenant_id: String,
    database: String,
    collection: String,
    upstream_cursor_id: i64,
}

pub struct MongoCursorRegistry {
    next_id: AtomicI64,
    cursors: Mutex<HashMap<i64, CursorBinding>>,
}

impl Default for MongoCursorRegistry {
    fn default() -> Self {
        let seed = (Uuid::new_v4().as_u128() as u64 & i64::MAX as u64).max(1) as i64;
        Self { next_id: AtomicI64::new(seed), cursors: Mutex::new(HashMap::new()) }
    }
}

impl MongoCursorRegistry {
    pub fn register(&self, tenant_id: &str, database: &str, collection: &str, upstream_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        for _ in 0..32 {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
            if let std::collections::hash_map::Entry::Vacant(entry) = cursors.entry(candidate) {
                entry.insert(CursorBinding { tenant_id: tenant_id.to_owned(), database: database.to_owned(), collection: collection.to_owned(), upstream_cursor_id });
                return Ok(candidate);
            }
        }
        Err(MongoPolicyError::CursorCollision)
    }

    pub fn resolve_get_more(&self, tenant_id: &str, database: &str, collection: &str, client_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let binding = cursors.get(&client_cursor_id).ok_or(MongoPolicyError::UnknownCursor)?;
        if binding.tenant_id != tenant_id || binding.database != database || binding.collection != collection {
            return Err(MongoPolicyError::CrossTenantCursor);
        }
        Ok(binding.upstream_cursor_id)
    }

    pub fn authorize_kill(&self, tenant_id: &str, database: &str, collection: &str, client_cursor_ids: &[i64]) -> Result<Vec<i64>, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let mut upstream_ids = Vec::with_capacity(client_cursor_ids.len());
        for id in client_cursor_ids {
            let binding = cursors.get(id).ok_or(MongoPolicyError::UnknownCursor)?;
            if binding.tenant_id != tenant_id || binding.database != database || binding.collection != collection {
                return Err(MongoPolicyError::CrossTenantCursor);
            }
            upstream_ids.push(binding.upstream_cursor_id);
        }
        for id in client_cursor_ids { cursors.remove(id); }
        Ok(upstream_ids)
    }

    pub fn release(&self, tenant_id: &str, client_cursor_id: i64) -> Result<i64, MongoPolicyError> {
        let mut cursors = self.cursors.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        let binding = cursors.get(&client_cursor_id).ok_or(MongoPolicyError::UnknownCursor)?;
        if binding.tenant_id != tenant_id { return Err(MongoPolicyError::CrossTenantCursor); }
        Ok(cursors.remove(&client_cursor_id).expect("cursor was checked").upstream_cursor_id)
    }
}

#[derive(Default)]
pub struct MongoSessionRegistry {
    sessions: Mutex<HashMap<Vec<u8>, String>>,
}

impl MongoSessionRegistry {
    pub fn bind(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        let mut sessions = self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        match sessions.get(&key) {
            Some(owner) if owner != tenant_id => Err(MongoPolicyError::CrossTenantSession),
            Some(_) => Ok(()),
            None => { sessions.insert(key, tenant_id.to_owned()); Ok(()) }
        }
    }

    pub fn authorize(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        let sessions = self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?;
        match sessions.get(&key) {
            Some(owner) if owner == tenant_id => Ok(()),
            Some(_) => Err(MongoPolicyError::CrossTenantSession),
            None => Err(MongoPolicyError::UnknownSession),
        }
    }

    pub fn release(&self, tenant_id: &str, lsid: &Document) -> Result<(), MongoPolicyError> {
        self.authorize(tenant_id, lsid)?;
        let key = bson::to_vec(lsid).map_err(|_| MongoPolicyError::InvalidCommand("lsid could not be serialized".into()))?;
        self.sessions.lock().map_err(|_| MongoPolicyError::RegistryUnavailable)?.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    fn policy() -> MongoTenantPolicy {
        MongoTenantPolicy::new("tenant-a", "tenant_a_db").unwrap()
    }

    fn command(name: &str, value: Bson) -> Document {
        let mut command = Document::new();
        command.insert(name, value);
        command.insert("$db", "tenant_a_db");
        command
    }

    #[test]
    fn requires_exact_tenant_database() {
        let mut command = command("find", Bson::String("records".into()));
        command.insert("$db", "tenant_b_db");
        assert_eq!(policy().authorize(&command), Err(MongoPolicyError::WrongDatabase));
    }

    #[test]
    fn denies_admin_and_unknown_commands() {
        for name in ["listDatabases", "dropDatabase", "createUser", "mapReduce", "eval", "renameCollection"] {
            let command = command(name, Bson::Int32(1));
            assert!(matches!(policy().authorize(&command), Err(MongoPolicyError::UnsupportedCommand(_))));
        }
    }

    #[test]
    fn allows_scoped_find_and_rejects_javascript_predicates() {
        let mut safe = command("find", Bson::String("records".into()));
        safe.insert("filter", doc! { "status": "active" });
        assert_eq!(policy().authorize(&safe), Ok(MongoCommandKind::Find));

        let mut unsafe_query = command("find", Bson::String("records".into()));
        unsafe_query.insert("filter", doc! { "$where": "return true" });
        assert!(matches!(policy().authorize(&unsafe_query), Err(MongoPolicyError::UnsafeOperator(_))));
    }

    #[test]
    fn aggregate_allows_safe_pipeline_and_rejects_cross_database_lookup() {
        let mut safe = command("aggregate", Bson::String("records".into()));
        safe.insert("pipeline", vec![doc! { "$match": { "status": "active" } }, doc! { "$limit": 5 }]);
        assert_eq!(policy().authorize(&safe), Ok(MongoCommandKind::Aggregate));

        let mut cross_db = command("aggregate", Bson::String("records".into()));
        cross_db.insert("pipeline", vec![doc! { "$lookup": { "from": { "db": "tenant_b_db", "coll": "records" }, "pipeline": [], "as": "joined" } }]);
        assert_eq!(policy().authorize(&cross_db), Err(MongoPolicyError::CrossDatabaseStage));
    }

    #[test]
    fn aggregate_rejects_output_and_change_stream_stages() {
        for stage in [doc! { "$out": "exfiltration" }, doc! { "$merge": "exfiltration" }, doc! { "$changeStream": {} }] {
            let mut command = command("aggregate", Bson::String("records".into()));
            command.insert("pipeline", vec![stage]);
            assert!(matches!(policy().authorize(&command), Err(MongoPolicyError::UnsafePipelineStage(_))));
        }
    }

    #[test]
    fn update_upsert_and_reserved_tenant_field_mutations_are_denied() {
        let mut upsert = command("update", Bson::String("records".into()));
        upsert.insert("updates", vec![doc! { "q": {}, "u": { "$set": { "x": 1 } }, "upsert": true }]);
        assert!(matches!(policy().authorize(&upsert), Err(MongoPolicyError::InvalidCommand(_))));

        let mut reserved = command("update", Bson::String("records".into()));
        reserved.insert("updates", vec![doc! { "q": {}, "u": { "$set": { "_proxima_tenant_id": "tenant-b" } } }]);
        assert!(matches!(policy().authorize(&reserved), Err(MongoPolicyError::InvalidCommand(_))));
    }

    #[test]
    fn insert_metadata_is_stamped_by_policy_not_client() {
        let mut document = doc! { "value": "record" };
        policy().stamp_insert_document(&mut document).unwrap();
        assert_eq!(document.get_str(RESERVED_TENANT_FIELD).unwrap(), "tenant-a");

        let mut spoofed = Document::new();
        spoofed.insert(RESERVED_TENANT_FIELD, "tenant-b");
        assert!(policy().stamp_insert_document(&mut spoofed).is_err());
    }

    #[test]
    fn session_ids_are_bound_to_one_tenant() {
        let registry = MongoSessionRegistry::default();
        let lsid = doc! { "id": bson::Binary { subtype: bson::spec::BinarySubtype::Uuid, bytes: Uuid::new_v4().as_bytes().to_vec() } };
        registry.bind("tenant-a", &lsid).unwrap();
        registry.authorize("tenant-a", &lsid).unwrap();
        assert_eq!(registry.authorize("tenant-b", &lsid), Err(MongoPolicyError::CrossTenantSession));
        assert_eq!(registry.bind("tenant-b", &lsid), Err(MongoPolicyError::CrossTenantSession));
    }

    #[test]
    fn cursor_ids_are_opaque_and_tenant_bound() {
        let registry = MongoCursorRegistry::default();
        let client_id = registry.register("tenant-a", "tenant_a_db", "records", 991).unwrap();
        assert_ne!(client_id, 991);
        assert_eq!(registry.resolve_get_more("tenant-a", "tenant_a_db", "records", client_id).unwrap(), 991);
        assert_eq!(registry.resolve_get_more("tenant-b", "tenant_a_db", "records", client_id), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.release("tenant-b", client_id), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.release("tenant-a", client_id).unwrap(), 991);
    }

    #[test]
    fn kill_cursors_is_all_or_nothing_across_tenants() {
        let registry = MongoCursorRegistry::default();
        let a = registry.register("tenant-a", "tenant_a_db", "records", 1001).unwrap();
        let b = registry.register("tenant-b", "tenant_b_db", "records", 2002).unwrap();
        assert_eq!(registry.authorize_kill("tenant-a", "tenant_a_db", "records", &[a, b]), Err(MongoPolicyError::CrossTenantCursor));
        assert_eq!(registry.resolve_get_more("tenant-a", "tenant_a_db", "records", a).unwrap(), 1001);
        assert_eq!(registry.resolve_get_more("tenant-b", "tenant_b_db", "records", b).unwrap(), 2002);
        assert_eq!(registry.authorize_kill("tenant-a", "tenant_a_db", "records", &[a]).unwrap(), vec![1001]);
    }
}
