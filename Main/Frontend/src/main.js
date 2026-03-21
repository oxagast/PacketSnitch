const { app, BrowserWindow, ipcMain } = require("electron");
const fs = require("fs");
const path = require("path");

//const hostsPath = "/tmp/testcases/hosts.json";
let mainWindow;
const filePath = path.join("/tmp/testcases/", "hosts.json");

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1310,
    minHeight: 700,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
}

app.whenReady().then(() => {
  createWindow();
  let fileSent = false;
  // this function handles polling for the existence of the json
  // file (on disk) and sends its content to the renderer process
  // when found
  setInterval(() => {
    if (!fileSent && fs.existsSync(filePath)) {
      // here we read the file in
      const data = fs.readFileSync(filePath, "utf8");
      mainWindow.webContents.send("json-data", data);
      fileSent = true; // Prevent sending multiple times
    }
  }, 2000);
});
