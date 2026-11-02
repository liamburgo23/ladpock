use std::process::Command;
use tauri::State;

pub struct AppState;

#[tauri::command]
fn read_note(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_note(path: String, contents: String) -> Result<(), String> {
    write_file(&path, &contents)
}

fn write_file(path: &str, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| e.to_string())
}

#[tauri::command]
fn run_tool(_state: State<'_, AppState>, tool: String, args: Vec<String>) -> Result<String, String> {
    let out = Command::new(tool).args(args).output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[tauri::command]
async fn fetch_feed(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e| e.to_string())?;
    client.get(url).send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())
}

async fn start_sync_server() -> std::io::Result<()> {
    let _listener = tokio::net::TcpListener::bind("0.0.0.0:7777").await?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState)
        .invoke_handler(tauri::generate_handler![read_note, save_note, run_tool, fetch_feed])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
