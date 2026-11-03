const fs = require("fs/promises");
const path = require("path");
const { app, BrowserWindow, ipcMain, shell } = require("electron");

const NOTES_DIR = path.join(app.getPath("userData"), "notes");

function openSafely(url) {
  if (new URL(url).protocol === "https:") shell.openExternal(url);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: { preload: path.join(__dirname, "preload.js") },
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    openSafely(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event) => event.preventDefault());
  win.loadFile("index.html");
}

ipcMain.handle("save-note", async (event, name, contents) => {
  const target = path.join(NOTES_DIR, path.basename(name));
  if (!target.startsWith(NOTES_DIR + path.sep)) throw new Error("Invalid note name");
  await fs.writeFile(target, contents, "utf8");
  return true;
});

app.whenReady().then(createWindow);
