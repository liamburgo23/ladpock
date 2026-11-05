use rocket::{get, post, routes};

#[post("/invoices", data = "<body>")]
async fn create_invoice(db: Db, body: Json<NewInvoice>) -> Status {
    sqlx::query("INSERT INTO invoices (total) VALUES ($1)").bind(body.total).execute(&db).await.unwrap();
    Status::Created
}

fn rocket() -> Rocket<Build> {
    rocket::build().mount("/api", routes![create_invoice])
}
