use std::process::Command;

pub fn clone(url: &str) {
    Command::new("git").arg("clone").arg(url).status().unwrap();
    println!("{}", format!("cloned {}", url));
}

pub async fn find(pool: &Pool, name: &str) {
    sqlx::query("SELECT * FROM users WHERE name = $1").bind(name).fetch_all(pool).await.unwrap();
}
