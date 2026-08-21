use super::*;

pub(super) async fn ensure_database(
    pool: &PgPool,
    database: &str,
    role: &str,
    password: Option<&str>,
) -> Result<bool, DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(role) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    let exists: bool = sqlx::query_scalar("select exists(select 1 from pg_roles where rolname=$1)")
        .bind(role)
        .fetch_one(pool)
        .await
        .map_err(DriverError::internal)?;
    let created = !exists;
    if created {
        let password = password.ok_or_else(|| DriverError::bad("database role is missing"))?;
        if !password.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(DriverError::bad("unsafe generated database password"));
        }
        sqlx::query(AssertSqlSafe(format!(
            "create role \"{role}\" login password '{password}'"
        )))
        .execute(pool)
        .await
        .map_err(DriverError::internal)?;
    }
    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from pg_database where datname=$1)")
            .bind(database)
            .fetch_one(pool)
            .await
            .map_err(DriverError::internal)?;
    if !exists {
        sqlx::query(AssertSqlSafe(format!(
            "create database \"{database}\" owner \"{role}\""
        )))
        .execute(pool)
        .await
        .map_err(DriverError::internal)?;
    }
    Ok(created)
}

pub(super) fn safe_pg_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(super) async fn replace_database(
    state: &DriverState,
    database: &str,
) -> Result<(), DriverError> {
    replace_database_owned(state, database, "odoo").await
}

pub(super) async fn replace_database_owned(
    state: &DriverState,
    database: &str,
    owner: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(owner) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    sqlx::query(
        "select pg_terminate_backend(pid) from pg_stat_activity where datname=$1 and pid<>pg_backend_pid()",
    )
    .bind(database)
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from pg_database where datname=$1)")
            .bind(database)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    if exists {
        sqlx::query(AssertSqlSafe(format!("drop database \"{database}\"")))
            .execute(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    }
    sqlx::query(AssertSqlSafe(format!(
        "create database \"{database}\" owner \"{owner}\""
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

pub(super) async fn drop_database(state: &DriverState, database: &str) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    sqlx::query(
        "select pg_terminate_backend(pid) from pg_stat_activity where datname=$1 and pid<>pg_backend_pid()",
    )
    .bind(database)
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    sqlx::query(AssertSqlSafe(format!(
        "drop database if exists \"{database}\""
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

pub(super) async fn run_postgres_job(
    state: &DriverState,
    container: &str,
    command: Vec<String>,
) -> Result<(), DriverError> {
    run_postgres_job_as(
        state,
        container,
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        command,
    )
    .await
}

pub(super) async fn run_postgres_job_as(
    state: &DriverState,
    container: &str,
    username: &str,
    password: &str,
    command: Vec<String>,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(username) {
        return Err(DriverError::bad("unsafe PostgreSQL job credential"));
    }
    let pgpass = pgpass_line(state, username, password);
    run_docker_job_with_secrets(
        state,
        container,
        json!({
            "Image":state.config.postgres_image,
            "Cmd":command,
            "Env":["PGPASSFILE=/run/mb-job-secrets/pgpass"],
            "Labels":{"mb.kind":"postgres-lifecycle-job"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("{}:/backups",state.config.backup_volume)]
            }
        }),
        &[("pgpass", &pgpass)],
    )
    .await
}

pub(super) fn postgres_admin_pgpass(state: &DriverState) -> String {
    pgpass_line(
        state,
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
    )
}

fn pgpass_line(state: &DriverState, username: &str, password: &str) -> String {
    let escape = |value: &str| value.replace('\\', "\\\\").replace(':', "\\:");
    format!(
        "{}:{}:*:{}:{}",
        escape(&state.config.postgres_host),
        state.config.postgres_port,
        escape(username),
        escape(password)
    )
}
