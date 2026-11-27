// SQL built from request values (sqlx, rusqlite, tokio-postgres, diesel, sea-orm).
use axum::extract::Query;
use sea_orm::{DatabaseBackend, Statement};
use sqlx::PgPool;

pub async fn find_user(pool: &PgPool, q: Query<Search>) -> sqlx::Result<Vec<User>> {
    let rows = sqlx::query_as::<_, User>(&format!("SELECT * FROM users WHERE name = '{}'", q.name)).fetch_all(pool).await?;
    sqlx::query(&format!("DELETE FROM sessions WHERE user = '{}'", q.name)).execute(pool).await?;
    Ok(rows)
}

pub fn rusqlite_lookup(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<i64> {
    conn.execute(&format!("UPDATE users SET seen = 1 WHERE name = '{}'", name), [])?;
    conn.query_row(&format!("SELECT id FROM users WHERE name = '{name}'"), [], |row| row.get(0))
}

pub async fn pg_lookup(client: &tokio_postgres::Client, name: &str) -> Result<(), tokio_postgres::Error> {
    client.batch_execute(&("DELETE FROM audit WHERE actor = '".to_string() + name + "'")).await?;
    Ok(())
}

pub fn diesel_lookup(name: &str) {
    let _query = diesel::sql_query(format!("SELECT * FROM users WHERE name = '{}'", name));
}

pub fn seaorm_lookup(name: &str) -> Statement {
    Statement::from_string(DatabaseBackend::Postgres, format!("SELECT * FROM users WHERE name = '{}'", name))
}

pub fn build_report_sql(table: &str, filter: &str) -> String {
    let sql = format!("SELECT * FROM {} WHERE {}", table, filter);
    let mut where_clause = String::from(" WHERE 1 = 1");
    where_clause.push_str(filter);
    sql + &where_clause
}

pub async fn count_by_status(pool: &PgPool, status: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar::<_, i64>(&format!(
        "SELECT count(*) FROM jobs WHERE status = '{}'",
        status
    ))
    .fetch_one(pool)
    .await
}

pub async fn by_owner(pool: &PgPool, owner: &str) -> sqlx::Result<Vec<User>> {
    let sql = format!("SELECT * FROM users WHERE owner = '{owner}'");
    sqlx::query_as(&sql).fetch_all(pool).await
}
