const fs = require("fs");
const { exec } = require("child_process");
const { app, BrowserWindow, ipcMain, shell } = require("electron");

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      preload: __dirname + "/preload.js",
    },
  });
  win.loadURL("http://app.example.dev/dashboard");
}

ipcMain.handle("save-file", async (event, filePath, contents) => {
  fs.writeFileSync(filePath, contents);
  return true;
});

ipcMain.handle("run-tool", async (event, command) => {
  exec(command);
});

ipcMain.on("open-link", (event, url) => {
  shell.openExternal(url);
});

app.whenReady().then(createWindow);
