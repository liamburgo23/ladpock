use actix_web::{get, post, web, HttpResponse};

#[post("/notes")]
async fn create_note(pool: web::Data<Pool>, body: web::Json<NewNote>) -> HttpResponse {
    sqlx::query("INSERT INTO notes (body) VALUES ($1)").bind(&body.text).execute(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().finish()
}

#[get("/notes/{id}")]
async fn read_note(session: Session, pool: web::Data<Pool>, id: web::Path<i64>) -> HttpResponse {
    let row = sqlx::query_as("SELECT * FROM notes WHERE id = $1").bind(*id).fetch_one(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(row)
}
