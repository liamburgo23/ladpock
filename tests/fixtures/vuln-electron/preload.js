const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ipc", ipcRenderer);

contextBridge.exposeInMainWorld("bridge", {
  send: (channel, data) => ipcRenderer.send(channel, data),
});
