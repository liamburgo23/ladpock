use axum::{routing::{get, post, delete}, Router, Json, extract::Path};

fn app() -> Router {
    Router::new()
        .route("/orders", get(list_orders).post(create_order))
        .route("/orders/:id", delete(delete_order))
        .nest("/api/me", me_routes())
}

fn me_routes() -> Router {
    Router::new().route("/orders/:id", get(read_order))
}

async fn list_orders(user: AuthUser, pool: Pool) -> Json<Vec<Order>> {
    let rows = sqlx::query_as("SELECT * FROM orders WHERE user_id = $1").bind(user.id).fetch_all(&pool).await.unwrap();
    Json(rows)
}

async fn create_order(pool: Pool, Json(body): Json<NewOrder>) {
    sqlx::query("INSERT INTO orders (sku) VALUES ($1)").bind(body.sku).execute(&pool).await.unwrap();
}

async fn delete_order(pool: Pool, Path(id): Path<i64>) {
    sqlx::query("DELETE FROM orders WHERE id = $1").bind(id).execute(&pool).await.unwrap();
}

async fn read_order(user: AuthUser, pool: Pool, Path(id): Path<i64>) -> Json<Order> {
    Json(sqlx::query_as("SELECT * FROM orders WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap())
}
