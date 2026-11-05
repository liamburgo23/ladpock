use axum::{routing::{get, delete}, Router, Json, extract::Path, middleware};

fn app() -> Router {
    Router::new()
        .route("/orders", get(list_orders))
        .route("/orders/:id", delete(delete_order))
        .route_layer(middleware::from_fn(require_auth))
}

async fn list_orders(user: AuthUser, pool: Pool) -> Json<Vec<Order>> {
    Json(sqlx::query_as("SELECT * FROM orders WHERE user_id = $1").bind(user.id).fetch_all(&pool).await.unwrap())
}

async fn delete_order(user: AuthUser, pool: Pool, Path(id): Path<i64>) {
    sqlx::query("DELETE FROM orders WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&pool).await.unwrap();
}
