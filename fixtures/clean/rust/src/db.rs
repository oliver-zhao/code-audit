// SQL with bind parameters and compile-time checked macros.
use axum::extract::Query;
use sea_orm::{DatabaseBackend, Statement};
use sqlx::{PgPool, Postgres, QueryBuilder};

pub async fn find_user(pool: &PgPool, q: Query<Search>) -> sqlx::Result<Vec<User>> {
    let rows = sqlx::query_as::<_, User>("SELECT * FROM users WHERE name = $1").bind(&q.name).fetch_all(pool).await?;
    sqlx::query!("DELETE FROM sessions WHERE user = $1", q.name).execute(pool).await?;
    Ok(rows)
}

pub fn rusqlite_lookup(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<i64> {
    conn.execute("UPDATE users SET seen = 1 WHERE name = ?1", rusqlite::params![name])?;
    conn.query_row("SELECT id FROM users WHERE name = ?1", [name], |row| row.get(0))
}

pub async fn pg_lookup(client: &tokio_postgres::Client, name: &str) -> Result<(), tokio_postgres::Error> {
    client.execute("DELETE FROM audit WHERE actor = $1", &[&name]).await?;
    Ok(())
}

pub fn diesel_lookup(name: &str) {
    let _query = diesel::sql_query("SELECT * FROM users WHERE name = $1").bind::<diesel::sql_types::Text, _>(name);
}

pub fn seaorm_lookup(name: &str) -> Statement {
    Statement::from_sql_and_values(DatabaseBackend::Postgres, "SELECT * FROM users WHERE name = $1", [name.into()])
}

pub fn build_report_sql(filter: &str) -> QueryBuilder<'_, Postgres> {
    let mut query_builder = QueryBuilder::new("SELECT * FROM reports WHERE owner = ");
    query_builder.push_bind(filter);
    query_builder
}

pub async fn create_database(pool: &PgPool, name: &str) -> sqlx::Result<()> {
    sqlx::query(&format!("CREATE DATABASE {}", quote_identifier(name))).execute(pool).await?;
    Ok(())
}
