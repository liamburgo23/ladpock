use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

fn notes_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map(|d| d.join("notes")).map_err(|e| e.to_string())
}

/// Resolve a note name inside the notes folder, refusing anything that escapes it.
fn inside_notes(app: &AppHandle, name: &str) -> Result<PathBuf, String> {
    let base = notes_dir(app)?.canonicalize().map_err(|e| e.to_string())?;
    let candidate = base.join(Path::new(name).file_name().ok_or("bad name")?);
    if !candidate.starts_with(&base) {
        return Err("outside the notes folder".into());
    }
    Ok(candidate)
}

#[tauri::command]
fn read_note(app: AppHandle, file_name: String) -> Result<String, String> {
    let path = inside_notes(&app, &file_name)?;
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_note(app: AppHandle, file_name: String, contents: String) -> Result<(), String> {
    let path = inside_notes(&app, &file_name)?;
    std::fs::write(path, contents).map_err(|e| e.to_string())
}

#[tauri::command]
fn word_count(text: String) -> usize {
    text.split_whitespace().count()
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![read_note, save_note, word_count])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
