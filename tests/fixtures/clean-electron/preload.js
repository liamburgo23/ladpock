const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("notes", {
  save: (name, contents) => ipcRenderer.invoke("save-note", name, contents),
});
