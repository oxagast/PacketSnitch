const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("jsonapi", {
  onJsonData: (callback) => {
    ipcRenderer.on("json-data", (event, hostsJsonData) => {
      callback(hostsJsonData);
    });
  },
});

contextBridge.exposeInMainWorld("snitchapi", {
  runBackendCommand: (filename, useLLM) =>
    ipcRenderer.invoke("run-backend-command", filename, useLLM),
});

contextBridge.exposeInMainWorld("getfileapi", {
  selectFile: () => ipcRenderer.invoke("select-file"),
});

contextBridge.exposeInMainWorld("api", {
  onError: (callback) => {
    ipcRenderer.on("backend-error", (_event, message) => {
      callback(message);
    });
  },
});

contextBridge.exposeInMainWorld("fsize", {
  getFSize: () => ipcRenderer.invoke("file-size"), // Expose this method to renderer
});

contextBridge.exposeInMainWorld("saveapi", {
  saveJson: () => ipcRenderer.invoke("save-json"),
});
