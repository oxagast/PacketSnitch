const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  onJsonData: (callback) => {
    ipcRenderer.on("json-data", (event, data) => {
      callback(data);
    });
  },
});
