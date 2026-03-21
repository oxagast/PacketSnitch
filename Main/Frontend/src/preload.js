const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  onJsonData: (callback) => {
    ipcRenderer.on("json-data", (event, data) => {
      callback(data);
    });
  },
});

contextBridge.exposeInMainWorld("apicomm", {
  runBackendCommand: (filename) =>
    ipcRenderer.invoke("run-backend-command", filename),
});
