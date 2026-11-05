use std::process::Command;

pub fn clone(url: &str) {
    Command::new("sh").arg("-c").arg(format!("git clone {}", url)).status().unwrap();
}

pub async fn find(pool: &Pool, name: &str) {
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name)).fetch_all(pool).await.unwrap();
}
