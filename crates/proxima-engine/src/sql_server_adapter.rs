//! SQL Server catalog adapter.
//!
//! The adapter requires encrypted TDS with certificate validation, inventories
//! native principals/permissions/RLS predicates and fails closed until the
//! SESSION_CONTEXT trust boundary and independent tenant probes are verified.

use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::native_policy_plans::compile_sql_server;
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, Operation, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tiberius::{Client, Config, EncryptionLevel};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

pub struct SqlServerCatalogAdapter {
    target_id: String,
    database_name: String,
    connection_string: String,
}

impl SqlServerCatalogAdapter {
    pub fn new(target_id: impl Into<String>, database_name: impl Into<String>, connection_string: impl Into<String>) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        let connection_string = connection_string.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || database_name.trim().is_empty() || database_name.len() > 128 || database_name.contains('\0')
            || connection_string.trim().is_empty() || connection_string.len() > 4096 {
            return Err(error("invalid_sql_server_target", "A bounded target ID, database name and connection string are required."));
        }
        let normalized = connection_string.to_ascii_lowercase().replace(' ', "");
        if ["trustservercertificate=true","trustservercertificate=yes","trustservercertificate=1","encrypt=false","encrypt=no","encrypt=0"].iter().any(|option| normalized.contains(option)) {
            return Err(error("sql_server_tls_verification_required", "SQL Server connections must require encryption and certificate/hostname verification; TrustServerCertificate=true and Encrypt=false are forbidden."));
        }
        if ["integratedsecurity=true","integratedsecurity=yes"].iter().any(|option| normalized.contains(option)) {
            return Err(error("sql_server_authentication_mode_unsupported", "This adapter build requires SQL Server username/password authentication; integrated Windows/Kerberos authentication is not enabled."));
        }
        Config::from_ado_string(&connection_string)
            .map_err(|_| error("invalid_sql_server_connection_config", "The SQL Server connection string could not be parsed."))?;
        Ok(Self { target_id, database_name, connection_string })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("sql_server_target_mismatch", "The request does not match this adapter's registered SQL Server target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<Client<tokio_util::compat::Compat<TcpStream>>, AdapterError> {
        let mut config = Config::from_ado_string(&self.connection_string)
            .map_err(|_| error("invalid_sql_server_connection_config", "The SQL Server connection string could not be parsed."))?;
        config.encryption(EncryptionLevel::Required);
        let address = config.get_addr();
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address))
            .await.map_err(|_| error("sql_server_connection_timeout", "SQL Server TCP connection exceeded the ten-second deadline."))?
            .map_err(db_error)?;
        tcp.set_nodelay(true).map_err(db_error)?;
        let mut client = tokio::time::timeout(Duration::from_secs(15), Client::connect(config, tcp.compat_write()))
            .await.map_err(|_| error("sql_server_tls_login_timeout", "SQL Server encrypted login exceeded the fifteen-second deadline."))?
            .map_err(db_error)?;
        let rows = client.simple_query(
            "SELECT DB_NAME() AS database_name, ORIGINAL_LOGIN() AS login_name, USER_NAME() AS database_user, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS server_version, CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS product_major_version, CONVERT(int,SERVERPROPERTY('EngineEdition')) AS engine_edition, CONVERT(bit,HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION')) AS can_view_definition, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin, IS_SRVROLEMEMBER('securityadmin') AS is_securityadmin, IS_SRVROLEMEMBER('serveradmin') AS is_serveradmin, IS_SRVROLEMEMBER('setupadmin') AS is_setupadmin, IS_SRVROLEMEMBER('dbcreator') AS is_dbcreator, IS_SRVROLEMEMBER('processadmin') AS is_processadmin, IS_SRVROLEMEMBER('diskadmin') AS is_diskadmin, IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin, IS_MEMBER('db_owner') AS is_db_owner, IS_MEMBER('db_ddladmin') AS is_db_ddladmin, IS_MEMBER('db_securityadmin') AS is_db_securityadmin, IS_MEMBER('db_accessadmin') AS is_db_accessadmin, IS_MEMBER('db_datawriter') AS is_db_datawriter, CONVERT(bit,CASE WHEN (HAS_PERMS_BY_NAME(NULL, 'SERVER', 'CONTROL SERVER')=1 OR HAS_PERMS_BY_NAME(NULL, 'SERVER', 'ALTER ANY LOGIN')=1 OR HAS_PERMS_BY_NAME(NULL, 'SERVER', 'ALTER ANY SERVER ROLE')=1 OR HAS_PERMS_BY_NAME(NULL, 'SERVER', 'ALTER ANY DATABASE')=1 OR EXISTS(SELECT 1 FROM sys.server_principals login_principal WHERE HAS_PERMS_BY_NAME(login_principal.name, 'LOGIN', 'IMPERSONATE')=1)) THEN 1 ELSE 0 END) AS has_server_mutation_privileges, CONVERT(bit,CASE WHEN (HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE')=1 OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY SCHEMA')=1 OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL')=1 OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY USER')=1 OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY ROLE')=1 OR EXISTS(SELECT 1 FROM sys.schemas schema_principal WHERE HAS_PERMS_BY_NAME(schema_principal.name, 'SCHEMA', 'ALTER')=1 OR HAS_PERMS_BY_NAME(schema_principal.name, 'SCHEMA', 'CONTROL')=1 OR HAS_PERMS_BY_NAME(schema_principal.name, 'SCHEMA', 'TAKE OWNERSHIP')=1)) THEN 1 ELSE 0 END) AS has_database_mutation_privileges, CONVERT(bit,CASE WHEN EXISTS(SELECT 1 FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'INSERT')=1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'UPDATE')=1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'DELETE')=1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'ALTER')=1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'CONTROL')=1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name)+'.'+QUOTENAME(t.name), 'OBJECT', 'TAKE OWNERSHIP')=1) THEN 1 ELSE 0 END) AS has_object_mutation_privileges"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let row = rows.first().ok_or_else(|| error("sql_server_identity_unavailable", "SQL Server did not return authenticated connection identity metadata."))?;
        let database = row.get::<&str,_>("database_name").unwrap_or_default();
        if database != self.database_name {
            return Err(error("sql_server_database_mismatch", "The authenticated connection reached a different SQL Server database."));
        }
        let sysadmin = row.get::<i32,_>("is_sysadmin").unwrap_or(0) == 1;
        let elevated_server_role = ["is_securityadmin", "is_serveradmin", "is_setupadmin", "is_dbcreator", "is_processadmin", "is_diskadmin", "is_bulkadmin"]
            .iter()
            .any(|column| row.get::<i32,_>(*column).unwrap_or(0) == 1);
        let elevated_database_role = ["is_db_owner", "is_db_ddladmin", "is_db_securityadmin", "is_db_accessadmin", "is_db_datawriter"]
            .iter()
            .any(|column| row.get::<i32,_>(*column).unwrap_or(0) == 1);
        let mutation_privileges = row.get::<bool,_>("has_server_mutation_privileges").unwrap_or(true)
            || row.get::<bool,_>("has_database_mutation_privileges").unwrap_or(true)
            || row.get::<bool,_>("has_object_mutation_privileges").unwrap_or(true);
        if sysadmin || elevated_server_role || elevated_database_role || mutation_privileges {
            return Err(error("unsafe_sql_server_inspection_principal", "Use a dedicated read-only SQL Server inspection principal; sysadmin, elevated fixed server/database roles and effective database/object mutation privileges are rejected."));
        }
        Ok(client)
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.as_ref().is_some_and(|schema| schema.trim().is_empty() || schema.len() > 128 || schema.contains('\0')) {
            return Err(error("invalid_sql_server_schema", "The requested SQL Server schema name is invalid."));
        }
        let mut client = self.connect_checked().await?;
        let identity_rows = client.simple_query(
            "SELECT DB_NAME() AS database_name, ORIGINAL_LOGIN() AS login_name, USER_NAME() AS database_user, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS server_version, CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS product_major_version, CONVERT(int,SERVERPROPERTY('EngineEdition')) AS engine_edition, CONVERT(bit,HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION')) AS can_view_definition, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let identity = identity_rows.first().ok_or_else(|| error("sql_server_identity_unavailable", "SQL Server identity metadata was unavailable."))?;
        let can_view_definition = identity.get::<bool,_>("can_view_definition").unwrap_or(false);
        let is_sysadmin = identity.get::<i32,_>("is_sysadmin").unwrap_or(0) == 1;
        let product_major_version = identity.get::<i32,_>("product_major_version").unwrap_or(0);
        let engine_edition = identity.get::<i32,_>("engine_edition").unwrap_or(0);
        if product_major_version < 13 && !matches!(engine_edition, 5 | 8) {
            return Err(error("sql_server_version_unsupported", "The SQL Server adapter requires SQL Server 2016+ or Azure SQL Database/Managed Instance for native row-level security catalog support."));
        }
        let mut resources = Vec::new();

        let table_rows = client.simple_query(
            "SELECT TOP (10001) s.name AS schema_name,t.name AS object_name,t.object_id,COALESCE(USER_NAME(t.principal_id),USER_NAME(s.principal_id)) AS owner_name,t.temporal_type_desc,t.is_memory_optimized,t.is_filetable,t.is_tracked_by_cdc FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id ORDER BY s.name,t.name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let table_inventory_truncated = table_rows.len() > 10_000;
        for row in table_rows.into_iter().take(10_000) {
            let schema = row.get::<&str,_>("schema_name").unwrap_or_default().to_owned();
            if request.namespace.as_deref().is_some_and(|wanted| wanted != schema.as_str()) { continue; }
            let name = row.get::<&str,_>("object_name").unwrap_or_default().to_owned();
            let object_id = row.get::<i32,_>("object_id").unwrap_or_default();
            let columns = client.query(
                "SELECT c.name,TYPE_NAME(c.user_type_id) AS data_type,c.is_nullable,c.is_computed,c.is_identity FROM sys.columns c WHERE c.object_id=@P1 ORDER BY c.column_id",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let permissions = client.query(
                "SELECT principal.name AS grantee,permission.permission_name,permission.state_desc,CONVERT(int,permission.minor_id) AS minor_id,column_info.name AS column_name FROM sys.database_permissions permission LEFT JOIN sys.database_principals principal ON principal.principal_id=permission.grantee_principal_id LEFT JOIN sys.columns column_info ON column_info.object_id=permission.major_id AND column_info.column_id=permission.minor_id WHERE permission.class_desc='OBJECT_OR_COLUMN' AND permission.major_id=@P1 ORDER BY principal.name,permission.permission_name,permission.minor_id",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let indexes = client.query(
                "SELECT index_info.name,index_info.type_desc,index_info.is_unique,index_info.is_primary_key,index_info.is_unique_constraint,index_info.is_disabled,index_info.has_filter,index_info.filter_definition,CONVERT(int,index_column.key_ordinal) AS key_ordinal,index_column.is_included_column,column_info.name AS column_name FROM sys.indexes index_info LEFT JOIN sys.index_columns index_column ON index_column.object_id=index_info.object_id AND index_column.index_id=index_info.index_id LEFT JOIN sys.columns column_info ON column_info.object_id=index_column.object_id AND column_info.column_id=index_column.column_id WHERE index_info.object_id=@P1 AND index_info.index_id > 0 ORDER BY index_info.index_id,index_column.key_ordinal,index_column.index_column_id",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let partition_metadata = client.query(
                "SELECT partition_info.index_id,partition_info.partition_number,partition_info.data_compression_desc,data_space.name AS data_space_name,partition_scheme.name AS partition_scheme,partition_function.name AS partition_function,partition_function.type_desc AS partition_function_type,partition_function.boundary_value_on_right,CONVERT(int,partition_parameter.parameter_id) AS partition_parameter_id,TYPE_NAME(partition_parameter.user_type_id) AS partition_parameter_type,partition_value.boundary_id,CONVERT(nvarchar(4000),partition_value.value) AS boundary_value FROM sys.partitions partition_info JOIN sys.indexes index_info ON index_info.object_id=partition_info.object_id AND index_info.index_id=partition_info.index_id JOIN sys.data_spaces data_space ON data_space.data_space_id=index_info.data_space_id LEFT JOIN sys.partition_schemes partition_scheme ON partition_scheme.data_space_id=data_space.data_space_id LEFT JOIN sys.partition_functions partition_function ON partition_function.function_id=partition_scheme.function_id LEFT JOIN sys.partition_parameters partition_parameter ON partition_parameter.function_id=partition_function.function_id LEFT JOIN sys.partition_range_values partition_value ON partition_value.function_id=partition_function.function_id WHERE partition_info.object_id=@P1 ORDER BY partition_info.index_id,partition_info.partition_number,partition_value.boundary_id",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let foreign_keys = client.query(
                "SELECT fk.name,fk.is_disabled,fk.is_not_trusted,fk.delete_referential_action_desc,fk.update_referential_action_desc,parent_column.name AS parent_column,OBJECT_SCHEMA_NAME(fkc.referenced_object_id) AS referenced_schema,OBJECT_NAME(fkc.referenced_object_id) AS referenced_table,referenced_column.name AS referenced_column FROM sys.foreign_keys fk JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id=fk.object_id JOIN sys.columns parent_column ON parent_column.object_id=fkc.parent_object_id AND parent_column.column_id=fkc.parent_column_id JOIN sys.columns referenced_column ON referenced_column.object_id=fkc.referenced_object_id AND referenced_column.column_id=fkc.referenced_column_id WHERE fk.parent_object_id=@P1 ORDER BY fk.name,fkc.constraint_column_id",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let check_constraints = client.query(
                "SELECT name,definition,is_disabled,is_not_trusted FROM sys.check_constraints WHERE parent_object_id=@P1 ORDER BY name",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let default_constraints = client.query(
                "SELECT name,definition,parent_column_id FROM sys.default_constraints WHERE parent_object_id=@P1 ORDER BY name",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let predicates = client.query(
                "SELECT policy.name AS policy_name,policy.is_enabled,policy.is_schema_bound,predicate.predicate_type_desc,predicate.operation_desc,predicate.predicate_definition FROM sys.security_policies policy JOIN sys.security_predicates predicate ON predicate.object_id=policy.object_id WHERE predicate.target_object_id=@P1 ORDER BY policy.name,predicate.operation_desc",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            let triggers = client.query(
                "SELECT trigger_info.name,trigger_info.is_disabled,trigger_info.is_instead_of_trigger,module.definition,module.execute_as_principal_id FROM sys.triggers trigger_info LEFT JOIN sys.sql_modules module ON module.object_id=trigger_info.object_id WHERE trigger_info.parent_id=@P1 ORDER BY trigger_info.name",
                &[&object_id],
            ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
            resources.push(DiscoveredResource {
                namespace: Some(schema),
                name,
                kind: ResourceKind::Table,
                owner: row.get::<&str,_>("owner_name").map(str::to_owned),
                attributes: json!({
                    "temporal_type": row.get::<&str,_>("temporal_type_desc").unwrap_or_default(),
                    "memory_optimized": row.get::<bool,_>("is_memory_optimized").unwrap_or(false),
                    "is_filetable": row.get::<bool,_>("is_filetable").unwrap_or(false),
                    "change_data_capture": row.get::<bool,_>("is_tracked_by_cdc").unwrap_or(false),
                    "columns": columns.iter().map(|column| json!({
                        "name": column.get::<&str,_>("name").unwrap_or_default(),
                        "type": column.get::<&str,_>("data_type").unwrap_or_default(),
                        "nullable": column.get::<bool,_>("is_nullable").unwrap_or(true),
                        "computed": column.get::<bool,_>("is_computed").unwrap_or(false),
                        "identity": column.get::<bool,_>("is_identity").unwrap_or(false)
                    })).collect::<Vec<_>>(),
                    "indexes": indexes.iter().map(|index| json!({
                        "name": index.get::<&str,_>("name").unwrap_or_default(),
                        "type": index.get::<&str,_>("type_desc").unwrap_or_default(),
                        "unique": index.get::<bool,_>("is_unique").unwrap_or(false),
                        "primary_key": index.get::<bool,_>("is_primary_key").unwrap_or(false),
                        "unique_constraint": index.get::<bool,_>("is_unique_constraint").unwrap_or(false),
                        "disabled": index.get::<bool,_>("is_disabled").unwrap_or(false),
                        "has_filter": index.get::<bool,_>("has_filter").unwrap_or(false),
                        "filter": index.get::<&str,_>("filter_definition"),
                        "key_ordinal": index.get::<i32,_>("key_ordinal"),
                        "included": index.get::<bool,_>("is_included_column").unwrap_or(false),
                        "column": index.get::<&str,_>("column_name")
                    })).collect::<Vec<_>>(),
                    "partitions": partition_metadata.iter().map(|partition| json!({
                        "index_id": partition.get::<i32,_>("index_id").unwrap_or_default(),
                        "partition_number": partition.get::<i32,_>("partition_number").unwrap_or_default(),
                        "compression": partition.get::<&str,_>("data_compression_desc").unwrap_or_default(),
                        "data_space": partition.get::<&str,_>("data_space_name").unwrap_or_default(),
                        "partition_scheme": partition.get::<&str,_>("partition_scheme"),
                        "partition_function": partition.get::<&str,_>("partition_function"),
                        "partition_function_type": partition.get::<&str,_>("partition_function_type"),
                        "boundary_value_on_right": partition.get::<bool,_>("boundary_value_on_right"),
                        "partition_parameter_id": partition.get::<i32,_>("partition_parameter_id"),
                        "partition_parameter_type": partition.get::<&str,_>("partition_parameter_type"),
                        "boundary_id": partition.get::<i32,_>("boundary_id"),
                        "boundary_value": partition.get::<&str,_>("boundary_value")
                    })).collect::<Vec<_>>(),
                    "foreign_keys": foreign_keys.iter().map(|foreign_key| json!({
                        "name": foreign_key.get::<&str,_>("name").unwrap_or_default(),
                        "disabled": foreign_key.get::<bool,_>("is_disabled").unwrap_or(false),
                        "not_trusted": foreign_key.get::<bool,_>("is_not_trusted").unwrap_or(false),
                        "on_delete": foreign_key.get::<&str,_>("delete_referential_action_desc").unwrap_or_default(),
                        "on_update": foreign_key.get::<&str,_>("update_referential_action_desc").unwrap_or_default(),
                        "parent_column": foreign_key.get::<&str,_>("parent_column"),
                        "referenced_schema": foreign_key.get::<&str,_>("referenced_schema"),
                        "referenced_table": foreign_key.get::<&str,_>("referenced_table"),
                        "referenced_column": foreign_key.get::<&str,_>("referenced_column")
                    })).collect::<Vec<_>>(),
                    "check_constraints": check_constraints.iter().map(|constraint| json!({
                        "name": constraint.get::<&str,_>("name").unwrap_or_default(),
                        "definition": constraint.get::<&str,_>("definition"),
                        "disabled": constraint.get::<bool,_>("is_disabled").unwrap_or(false),
                        "not_trusted": constraint.get::<bool,_>("is_not_trusted").unwrap_or(false)
                    })).collect::<Vec<_>>(),
                    "default_constraints": default_constraints.iter().map(|constraint| json!({
                        "name": constraint.get::<&str,_>("name").unwrap_or_default(),
                        "definition": constraint.get::<&str,_>("definition"),
                        "column_id": constraint.get::<i32,_>("parent_column_id").unwrap_or_default()
                    })).collect::<Vec<_>>(),
                    "permissions": permissions.iter().map(|permission| json!({
                        "grantee": permission.get::<&str,_>("grantee").unwrap_or_default(),
                        "permission": permission.get::<&str,_>("permission_name").unwrap_or_default(),
                        "state": permission.get::<&str,_>("state_desc").unwrap_or_default(),
                        "column_id": permission.get::<i32,_>("minor_id").unwrap_or_default(),
                        "column": permission.get::<&str,_>("column_name")
                    })).collect::<Vec<_>>(),
                    "security_predicates": predicates.iter().map(|predicate| json!({
                        "policy": predicate.get::<&str,_>("policy_name").unwrap_or_default(),
                        "enabled": predicate.get::<bool,_>("is_enabled").unwrap_or(false),
                        "schema_bound": predicate.get::<bool,_>("is_schema_bound").unwrap_or(false),
                        "predicate_type": predicate.get::<&str,_>("predicate_type_desc").unwrap_or_default(),
                        "operation": predicate.get::<&str,_>("operation_desc").unwrap_or_default(),
                        "definition": predicate.get::<&str,_>("predicate_definition")
                    })).collect::<Vec<_>>(),
                    "triggers": triggers.iter().map(|trigger| json!({
                        "name": trigger.get::<&str,_>("name").unwrap_or_default(),
                        "disabled": trigger.get::<bool,_>("is_disabled").unwrap_or(false),
                        "instead_of": trigger.get::<bool,_>("is_instead_of_trigger").unwrap_or(false),
                        "definition": trigger.get::<&str,_>("definition"),
                        "execute_as_principal_id": trigger.get::<i32,_>("execute_as_principal_id")
                    })).collect::<Vec<_>>()
                }),
            });
        }

        let view_rows = client.simple_query(
            "SELECT TOP (10001) s.name AS schema_name,v.name AS object_name,v.object_id,v.with_check_option,CONVERT(bit,OBJECTPROPERTY(v.object_id,'IsSchemaBound')) AS is_schema_bound,m.definition,USER_NAME(o.principal_id) AS owner_name FROM sys.views v JOIN sys.schemas s ON s.schema_id=v.schema_id JOIN sys.objects o ON o.object_id=v.object_id LEFT JOIN sys.sql_modules m ON m.object_id=v.object_id ORDER BY s.name,v.name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let view_inventory_truncated = view_rows.len() > 10_000;
        for row in view_rows.into_iter().take(10_000) {
            let schema = row.get::<&str,_>("schema_name").unwrap_or_default().to_owned();
            if request.namespace.as_deref().is_some_and(|wanted| wanted != schema.as_str()) { continue; }
            resources.push(DiscoveredResource {
                namespace: Some(schema),
                name: row.get::<&str,_>("object_name").unwrap_or_default().to_owned(),
                kind: ResourceKind::View,
                owner: row.get::<&str,_>("owner_name").map(str::to_owned),
                attributes: json!({
                    "with_check_option": row.get::<bool,_>("with_check_option").unwrap_or(false),
                    "schema_bound": row.get::<bool,_>("is_schema_bound").unwrap_or(false),
                    "definition": row.get::<&str,_>("definition")
                }),
            });
        }

        let routine_rows = client.simple_query(
            "SELECT TOP (10001) s.name AS schema_name,o.name AS object_name,o.type_desc,USER_NAME(o.principal_id) AS owner_name,m.definition,m.execute_as_principal_id,m.is_schema_bound FROM sys.objects o JOIN sys.schemas s ON s.schema_id=o.schema_id LEFT JOIN sys.sql_modules m ON m.object_id=o.object_id WHERE o.type IN ('P','FN','IF','TF','FS','FT') ORDER BY s.name,o.name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let routine_inventory_truncated = routine_rows.len() > 10_000;
        for row in routine_rows.into_iter().take(10_000) {
            let schema = row.get::<&str,_>("schema_name").unwrap_or_default().to_owned();
            if request.namespace.as_deref().is_some_and(|wanted| wanted != schema.as_str()) { continue; }
            let type_desc = row.get::<&str,_>("type_desc").unwrap_or_default();
            let kind = if type_desc.contains("PROCEDURE") { ResourceKind::Procedure } else { ResourceKind::Function };
            resources.push(DiscoveredResource {
                namespace: Some(schema),
                name: row.get::<&str,_>("object_name").unwrap_or_default().to_owned(),
                kind,
                owner: row.get::<&str,_>("owner_name").map(str::to_owned),
                attributes: json!({
                    "type": type_desc,
                    "definition": row.get::<&str,_>("definition"),
                    "execute_as_principal_id": row.get::<i32,_>("execute_as_principal_id"),
                    "schema_bound": row.get::<bool,_>("is_schema_bound").unwrap_or(false)
                }),
            });
        }

        let database_options_rows = client.simple_query(
            "SELECT database_info.name,owner.name AS owner_name,database_info.is_trustworthy_on,database_info.is_db_chaining_on,database_info.is_read_committed_snapshot_on,CONVERT(int,database_info.compatibility_level) AS compatibility_level,database_info.containment_desc FROM sys.databases database_info LEFT JOIN sys.server_principals owner ON owner.sid=database_info.owner_sid WHERE database_info.database_id=DB_ID()"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let database_options = database_options_rows.first();
        let principals = client.simple_query(
            "SELECT principal.name,principal.type_desc,principal.authentication_type_desc,principal.is_fixed_role,principal.default_schema_name FROM sys.database_principals principal WHERE principal.principal_id = 1 OR principal.principal_id > 4 ORDER BY principal.name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let role_memberships = client.simple_query(
            "SELECT role_principal.name AS role_name,member_principal.name AS member_name FROM sys.database_role_members membership JOIN sys.database_principals role_principal ON role_principal.principal_id=membership.role_principal_id JOIN sys.database_principals member_principal ON member_principal.principal_id=membership.member_principal_id ORDER BY role_principal.name,member_principal.name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let object_permissions = client.simple_query(
            "SELECT OBJECT_SCHEMA_NAME(permission.major_id) AS schema_name,OBJECT_NAME(permission.major_id) AS object_name,principal.name AS grantee,permission.permission_name,permission.state_desc,CONVERT(int,permission.minor_id) AS minor_id FROM sys.database_permissions permission LEFT JOIN sys.database_principals principal ON principal.principal_id=permission.grantee_principal_id WHERE permission.class_desc='OBJECT_OR_COLUMN' ORDER BY schema_name,object_name,principal.name,permission.permission_name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let schema_permissions = client.simple_query(
            "SELECT schema_info.name AS schema_name,principal.name AS grantee,permission.permission_name,permission.state_desc FROM sys.database_permissions permission JOIN sys.database_principals principal ON principal.principal_id=permission.grantee_principal_id JOIN sys.schemas schema_info ON schema_info.schema_id=permission.major_id WHERE permission.class_desc='SCHEMA' ORDER BY schema_info.name,principal.name,permission.permission_name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let database_permissions = client.simple_query(
            "SELECT principal.name AS grantee,permission.permission_name,permission.state_desc FROM sys.database_permissions permission JOIN sys.database_principals principal ON principal.principal_id=permission.grantee_principal_id WHERE permission.class_desc='DATABASE' ORDER BY principal.name,permission.permission_name"
        ).await.map_err(db_error)?.into_first_result().await.map_err(db_error)?;
        let can_view_definition = identity.get::<bool,_>("can_view_definition").unwrap_or(false);
        let is_sysadmin = identity.get::<i32,_>("is_sysadmin").unwrap_or(0) == 1;
        let target_attributes = json!({
            "database": identity.get::<&str,_>("database_name").unwrap_or_default(),
            "original_login": identity.get::<&str,_>("login_name").unwrap_or_default(),
            "database_user": identity.get::<&str,_>("database_user").unwrap_or_default(),
            "server_version": identity.get::<&str,_>("server_version").unwrap_or_default(),
            "product_major_version": product_major_version,
            "engine_edition": engine_edition,
            "can_view_definition": can_view_definition,
            "is_sysadmin": is_sysadmin,
            "principals": principals.iter().map(|principal| json!({
                "name": principal.get::<&str,_>("name").unwrap_or_default(),
                "type": principal.get::<&str,_>("type_desc").unwrap_or_default(),
                "authentication": principal.get::<&str,_>("authentication_type_desc").unwrap_or_default(),
                "fixed_role": principal.get::<bool,_>("is_fixed_role").unwrap_or(false),
                "default_schema": principal.get::<&str,_>("default_schema_name")
            })).collect::<Vec<_>>(),
            "role_memberships": role_memberships.iter().map(|membership| json!({
                "role": membership.get::<&str,_>("role_name").unwrap_or_default(),
                "member": membership.get::<&str,_>("member_name").unwrap_or_default()
            })).collect::<Vec<_>>(),
            "object_permissions": object_permissions.iter().map(|permission| json!({
                "schema": permission.get::<&str,_>("schema_name"),
                "object": permission.get::<&str,_>("object_name"),
                "grantee": permission.get::<&str,_>("grantee").unwrap_or_default(),
                "permission": permission.get::<&str,_>("permission_name").unwrap_or_default(),
                "state": permission.get::<&str,_>("state_desc").unwrap_or_default(),
                "column_id": permission.get::<i32,_>("minor_id").unwrap_or_default()
            })).collect::<Vec<_>>(),
            "schema_permissions": schema_permissions.iter().map(|permission| json!({
                "schema": permission.get::<&str,_>("schema_name").unwrap_or_default(),
                "grantee": permission.get::<&str,_>("grantee").unwrap_or_default(),
                "permission": permission.get::<&str,_>("permission_name").unwrap_or_default(),
                "state": permission.get::<&str,_>("state_desc").unwrap_or_default()
            })).collect::<Vec<_>>(),
            "database_permissions": database_permissions.iter().map(|permission| json!({
                "grantee": permission.get::<&str,_>("grantee").unwrap_or_default(),
                "permission": permission.get::<&str,_>("permission_name").unwrap_or_default(),
                "state": permission.get::<&str,_>("state_desc").unwrap_or_default()
            })).collect::<Vec<_>>(),
            "database_options": database_options.map(|row| json!({
                "owner": row.get::<&str,_>("owner_name"),
                "trustworthy": row.get::<bool,_>("is_trustworthy_on").unwrap_or(false),
                "database_chaining": row.get::<bool,_>("is_db_chaining_on").unwrap_or(false),
                "read_committed_snapshot": row.get::<bool,_>("is_read_committed_snapshot_on").unwrap_or(false),
                "compatibility_level": row.get::<i32,_>("compatibility_level").unwrap_or_default(),
                "containment": row.get::<&str,_>("containment_desc").unwrap_or_default()
            })),
            "catalog_inventory_truncated": table_inventory_truncated || view_inventory_truncated || routine_inventory_truncated,
            "encrypted_transport_required": true
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({"target_id":self.target_id,"database_name":self.database_name,"target":target_attributes,"resources":resources}))
            .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize SQL Server catalog state."))?);
        let mut findings = Vec::new();
        if table_inventory_truncated || view_inventory_truncated || routine_inventory_truncated {
            findings.push(SecurityFinding {
                code: "sql_server_catalog_inventory_truncated".into(),
                resource: None,
                detail: "The visible catalog exceeded the 10,000-table, 10,000-view or 10,000-routine safety bound; discovery is truncated.".into(),
            });
        }
        if !can_view_definition && !is_sysadmin {
            findings.push(SecurityFinding {
                code: "sql_server_catalog_visibility_incomplete".into(),
                resource: None,
                detail: "The inspection principal lacks database VIEW DEFINITION and is not sysadmin; catalog visibility may be filtered.".into(),
            });
        }
        if database_options.is_some_and(|row| row.get::<bool,_>("is_trustworthy_on").unwrap_or(false)) {
            findings.push(SecurityFinding {
                code: "sql_server_database_trustworthy_enabled".into(),
                resource: None,
                detail: "The database TRUSTWORTHY option is enabled; review ownership and module execution paths for privilege escalation risk.".into(),
            });
        }
        if database_options.is_some_and(|row| row.get::<bool,_>("is_db_chaining_on").unwrap_or(false)) {
            findings.push(SecurityFinding {
                code: "sql_server_database_chaining_enabled".into(),
                resource: None,
                detail: "Cross-database ownership chaining is enabled and requires explicit review of cross-database privilege paths.".into(),
            });
        }
        if is_sysadmin {
            findings.push(SecurityFinding {
                code: "sql_server_inspection_principal_sysadmin".into(),
                resource: None,
                detail: "The catalog inspection principal is sysadmin. Use a dedicated least-privilege inspection identity for production assessments.".into(),
            });
        }
        Ok(DiscoverySnapshot {
            database_kind: DatabaseKind::SqlServer,
            target: request.target.clone(),
            completeness: if (can_view_definition || is_sysadmin) && !(table_inventory_truncated || view_inventory_truncated || routine_inventory_truncated) { InspectionCompleteness::Complete } else { InspectionCompleteness::Incomplete },
            target_attributes,
            resources,
            findings,
            fingerprint: Some(fingerprint),
            observed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn discover_bounded(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        tokio::time::timeout(std::time::Duration::from_secs(60), self.discover_inner(request))
            .await
            .map_err(|_| AdapterError {
                code: "sql_server_catalog_timeout".into(),
                detail: "SQL Server catalog discovery exceeded the sixty-second operation deadline.".into(),
                retryable: true,
            })?
    }

}

impl DatabaseAdapter for SqlServerCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::SqlServer,
            name: "Microsoft SQL Server catalog adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, policy_generation: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "Encrypted TDS catalog discovery covers tables, columns, object permissions, RLS predicates, triggers, views, routines, principals, role membership and database permissions. Trusted SESSION_CONTEXT binding, controlled deployment, independent semantic probes and signed admission remain unavailable.",
        }
    }

    fn discover<'a>(&'a self, request: &'a DiscoveryRequest) -> AdapterFuture<'a, Result<DiscoverySnapshot, AdapterError>> {
        Box::pin(async move { self.discover_bounded(request).await })
    }

    fn inspect<'a>(&'a self, request: &'a InspectionRequest) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
        Box::pin(async move {
            self.validate_target(&request.target)?;
            request.policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
            let _compiled_plan = compile_sql_server(&request.policy)?;
            let discovery = self.discover_bounded(&DiscoveryRequest { target: request.target.clone(), namespace: None }).await?;
            let mut findings = discovery.findings.clone();
            let mut resources = Vec::with_capacity(request.policy.resources.len());
            for protected in &request.policy.resources {
                if protected.resource.kind != ResourceKind::Table {
                    return Err(error("unsupported_sql_server_policy_resource", "The current SQL Server RLS compiler manages tables only."));
                }
                let protected_schema = protected.resource.namespace.as_deref().unwrap_or("dbo");
                let found = discovery.resources.iter().find(|resource| {
                    resource.namespace.as_deref() == Some(protected_schema) && resource.name == protected.resource.name
                        && resource.kind == ResourceKind::Table
                });
                let mut resource_findings = Vec::new();
                let Some(found) = found else {
                    resource_findings.push(finding("protected_resource_not_found", &protected.resource, "The registered SQL Server table was not visible in sys.tables."));
                    findings.extend(resource_findings.clone());
                    resources.push(ResourceInspection {
                        resource: protected.clone(), completeness: InspectionCompleteness::Incomplete,
                        posture: SecurityPosture::Blocked, verified_operations: Vec::new(),
                        findings: resource_findings, fingerprint: None,
                    });
                    continue;
                };
                let columns = found.attributes["columns"].as_array().cloned().unwrap_or_default();
                let tenant_column = columns.iter().find(|column| column["name"].as_str() == Some(protected.tenant_key.as_str()));
                match tenant_column {
                    None => resource_findings.push(finding("tenant_ownership_column_missing", &protected.resource, "The policy tenant ownership column does not exist.")),
                    Some(column) if column["nullable"].as_bool() != Some(false) =>
                        resource_findings.push(finding("tenant_ownership_column_nullable", &protected.resource, "The tenant ownership column permits NULL values.")),
                    _ => {}
                }
                let predicates = found.attributes["security_predicates"].as_array().cloned().unwrap_or_default();
                let enabled = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true));
                if !enabled {
                    resource_findings.push(finding("sql_server_rls_policy_missing_or_disabled", &protected.resource, "No enabled SQL Server security policy predicate protects this table."));
                }
                if predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(false)) {
                    resource_findings.push(finding("sql_server_disabled_rls_policy_present", &protected.resource, "One or more SQL Server RLS predicates are disabled and may leave an intended operation unprotected."));
                }
                if predicates.iter().any(|predicate| predicate["schema_bound"].as_bool() != Some(true)) {
                    resource_findings.push(finding("sql_server_rls_policy_not_schema_bound", &protected.resource, "An RLS security policy is not confirmed schema-bound."));
                }
                let has_filter = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true) && predicate["predicate_type"].as_str() == Some("FILTER"));
                let has_after_insert = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true) && predicate["operation"].as_str() == Some("AFTER INSERT"));
                let has_before_update = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true) && predicate["operation"].as_str() == Some("BEFORE UPDATE"));
                let has_after_update = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true) && predicate["operation"].as_str() == Some("AFTER UPDATE"));
                let has_before_delete = predicates.iter().any(|predicate| predicate["enabled"].as_bool() == Some(true) && predicate["operation"].as_str() == Some("BEFORE DELETE"));
                if protected.operations.contains(&Operation::Read) && !has_filter {
                    resource_findings.push(finding("sql_server_filter_predicate_missing", &protected.resource, "Read operations require an enabled FILTER predicate."));
                }
                if protected.operations.contains(&Operation::Create) && !has_after_insert {
                    resource_findings.push(finding("sql_server_insert_block_predicate_missing", &protected.resource, "Create operations require an AFTER INSERT block predicate."));
                }
                if protected.operations.contains(&Operation::Update) && !(has_before_update && has_after_update) {
                    resource_findings.push(finding("sql_server_update_block_predicates_incomplete", &protected.resource, "Update isolation requires both BEFORE UPDATE and AFTER UPDATE block predicates to prevent cross-tenant row reassignment."));
                }
                if protected.operations.contains(&Operation::Delete) && !has_before_delete {
                    resource_findings.push(finding("sql_server_delete_block_predicate_missing", &protected.resource, "Delete operations require a BEFORE DELETE block predicate."));
                }
                let predicate_function_identities = predicates.iter()
                    .filter_map(|predicate| predicate["definition"].as_str().and_then(predicate_function_identity))
                    .collect::<Vec<_>>();
                let predicate_functions = discovery.resources.iter().filter(|resource| {
                    resource.kind == ResourceKind::Function && predicate_function_identities.iter().any(|(schema, name)| {
                        name.eq_ignore_ascii_case(&resource.name)
                            && schema.as_deref().is_none_or(|schema| resource.namespace.as_deref().is_some_and(|actual| actual.eq_ignore_ascii_case(schema)))
                    })
                }).collect::<Vec<_>>();
                let predicate_definitions_visible = predicate_functions.iter().any(|function| function.attributes["definition"].as_str().is_some());
                if !predicates.is_empty() && (predicate_functions.is_empty() || !predicate_definitions_visible) {
                    resource_findings.push(finding("sql_server_predicate_function_definition_unavailable", &protected.resource, "The RLS predicate function definition was not visible in the catalog; its tenant identity source cannot be inspected."));
                } else if !predicate_functions.is_empty() && !predicate_functions.iter().any(|function| {
                    function.attributes["definition"].as_str().is_some_and(|definition| definition.to_ascii_uppercase().contains("SESSION_CONTEXT"))
                }) {
                    resource_findings.push(finding("sql_server_tenant_context_predicate_missing", &protected.resource, "The RLS predicate function definitions do not reference SESSION_CONTEXT; verify that they bind rows to authenticated tenant identity."));
                }
                if predicate_functions.iter().any(|function| function.attributes["schema_bound"].as_bool() != Some(true)) {
                    resource_findings.push(finding("sql_server_predicate_function_not_schema_bound", &protected.resource, "A predicate function is not confirmed schema-bound; SQL Server RLS predicate functions should be schema-bound."));
                }
                if predicate_functions.iter().any(|function| function.attributes["execute_as_principal_id"].as_i64().is_some()) {
                    resource_findings.push(finding("sql_server_predicate_function_execute_as", &protected.resource, "An RLS predicate function uses EXECUTE AS; review its effective permissions and tenant-boundary behavior."));
                }
                if found.attributes["triggers"].as_array().is_some_and(|triggers| triggers.iter().any(|trigger| trigger["execute_as_principal_id"].as_i64().is_some())) {
                    resource_findings.push(finding("sql_server_trigger_execute_as", &protected.resource, "A table trigger uses EXECUTE AS and requires review for elevated cross-tenant data access."));
                }
                resource_findings.push(finding("sql_server_session_context_trust_unverified", &protected.resource, "SESSION_CONTEXT is settable by a database session unless the application/gateway boundary prevents untrusted callers from setting tenant identity."));
                let resource_fingerprint = digest(&serde_json::to_vec(&found.attributes)
                    .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize SQL Server resource inspection."))?);
                findings.extend(resource_findings.clone());
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: discovery.completeness,
                    posture: SecurityPosture::NeedsAttention,
                    verified_operations: Vec::new(),
                    findings: resource_findings,
                    fingerprint: Some(resource_fingerprint),
                });
            }
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::SqlServer,
                target: request.target.clone(),
                completeness: discovery.completeness,
                posture: SecurityPosture::NeedsAttention,
                resources,
                findings,
                fingerprint: discovery.fingerprint,
                observed_at: discovery.observed_at,
            })
        })
    }

    fn compile_policy(&self, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> { compile_sql_server(policy) }

    fn verify<'a>(&'a self, policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::SqlServer || snapshot.target.target_id != self.target_id
                || snapshot.target.database_name != self.database_name {
                return Err(error("sql_server_snapshot_target_mismatch", "The inspection snapshot does not belong to this SQL Server adapter target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "sql_server_independent_tenant_probes_required".into(),
                resource: None,
                detail: format!("{} protected tables require own-tenant allow and cross-tenant deny probes for read/create/update/delete.", policy.resources.len()),
            });
            findings.push(SecurityFinding {
                code: "sql_server_runtime_tenant_binding_unavailable".into(),
                resource: None,
                detail: "No trusted SQL Server protocol gateway currently binds authenticated tenant identity to an unforgeable SESSION_CONTEXT value.".into(),
            });
            Ok(VerificationReport { model_version: SECURITY_MODEL_VERSION.into(), posture: SecurityPosture::Blocked, inspection: snapshot.completeness, findings })
        })
    }

    fn detect_drift<'a>(&'a self, target: &'a AdapterTarget, previous_fingerprint: Option<&'a str>) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
        Box::pin(async move {
            self.validate_target(target)?;
            if previous_fingerprint.is_some_and(|value| value.len() != 64 || hex::decode(value).map_or(true, |bytes| bytes.len() != 32)) {
                return Err(error("invalid_previous_fingerprint", "The previous fingerprint must be a 32-byte hexadecimal SHA-256 digest."));
            }
            let snapshot = self.discover_bounded(&DiscoveryRequest { target: target.clone(), namespace: None }).await?;
            Ok(DriftReport {
                database_kind: DatabaseKind::SqlServer, target: target.clone(),
                detected: previous_fingerprint.is_some_and(|previous| Some(previous) != snapshot.fingerprint.as_deref()),
                completeness: snapshot.completeness, previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: snapshot.fingerprint, findings: snapshot.findings, observed_at: snapshot.observed_at,
            })
        })
    }
}

fn predicate_function_identity(definition: &str) -> Option<(Option<String>, String)> {
    let call = definition.split('(').next()?.trim();
    let normalized = call.replace('[', "").replace(']', "");
    let parts = normalized.split('.').map(str::trim).filter(|part| !part.is_empty()).collect::<Vec<_>>();
    let name = parts.last()?.to_string();
    let schema = if parts.len() >= 2 { Some(parts[parts.len() - 2].to_string()) } else { None };
    Some((schema, name))
}

fn finding(code: &str, resource: &ResourceRef, detail: &str) -> SecurityFinding {
    SecurityFinding { code: code.into(), resource: Some(resource.clone()), detail: detail.into() }
}

fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex::encode(hash.finalize())
}

fn error(code: &str, detail: &str) -> AdapterError {
    AdapterError { code: code.into(), detail: detail.into(), retryable: false }
}

fn db_error(_error: impl std::fmt::Display) -> AdapterError {
    AdapterError { code: "sql_server_catalog_operation_failed".into(), detail: "The encrypted SQL Server catalog operation failed.".into(), retryable: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unverified_sql_server_transport_options() {
        assert!(SqlServerCatalogAdapter::new("target", "app", "Server=localhost;Database=app;TrustServerCertificate=true").is_err());
        assert!(SqlServerCatalogAdapter::new("target", "app", "Server=localhost;Database=app;Encrypt=false").is_err());
        assert!(SqlServerCatalogAdapter::new("target", "app", "Server=localhost;Database=app;Integrated Security=true").is_err());
    }

    #[test]
    fn extracts_schema_qualified_rls_predicate_function_names() {
        assert_eq!(predicate_function_identity("[security].[fn_tenant_access]([tenant_id])").as_ref(), Some(&(Some("security".into()), "fn_tenant_access".into())));
        assert_eq!(predicate_function_identity("security.fn_tenant_access([tenant_id])").as_ref(), Some(&(Some("security".into()), "fn_tenant_access".into())));
        assert_eq!(predicate_function_identity(""), None);
    }

    #[tokio::test]
    async fn verification_never_allows_catalog_only_sql_server_evidence() {
        use crate::security_core::{ProtectedResource, ResourceRef};
        let adapter = SqlServerCatalogAdapter::new("target", "app", "Server=localhost;Database=app;User Id=auditor;Password=example;Encrypt=True;TrustServerCertificate=False").unwrap();
        let policy = TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-policy".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef { namespace: Some("dbo".into()), name: "records".into(), kind: ResourceKind::Table },
                tenant_key: "tenant_id".into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        };
        let snapshot = InspectionSnapshot {
            database_kind: DatabaseKind::SqlServer,
            target: AdapterTarget { target_id: "target".into(), database_name: "app".into(), namespace: None },
            completeness: InspectionCompleteness::Complete,
            posture: SecurityPosture::Verified,
            resources: Vec::new(),
            findings: Vec::new(),
            fingerprint: Some("a".repeat(64)),
            observed_at: "2026-11-17T00:00:00Z".into(),
        };
        let report = adapter.verify(&policy, &snapshot).await.unwrap();
        assert_eq!(report.posture, SecurityPosture::Blocked);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn rejects_invalid_database_target() {
        assert!(SqlServerCatalogAdapter::new("", "app", "Server=localhost;Database=app").is_err());
        assert!(SqlServerCatalogAdapter::new("target", "", "Server=localhost;Database=app").is_err());
    }
}
