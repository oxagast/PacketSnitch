const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const process = require("process");
let mainWindow;
filePath = ""
const os = require("os");

const platform = os.platform();
if (platform === "linux") {
	fs.rmdir("/tmp/testcases", { recursive: true }, (err) => {
  if (err) console.error(err);
});
 filePath = path.join("/tmp/testcases/", "hosts.json");
}
else if (platform === "win32") {
	fs.rmdir("C:\\Windows\\Temp\\testcases", { recursive: true }, (err) => {
  if (err) console.error(err);
});
	filePath = "C:\\Windows\\Temp\\testcases\\hosts.json";
}
else {
	console.log("Err, OS not supported.");
}



function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1310,
    minHeight: 700,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
    contextIsolation: true,
    nodeIntegration: false,
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
}

app.whenReady().then(() => {
  createWindow();
  let fileSent = false;
  // this function handles polling for the existence of the json
  require("./back-comm");
  // remove the tmp directory on startup to ensure we have a clean directory
  // if a pcap file is opened, then we start polling for the
  //json file to be created by the backend, and send it to the
  // back-comm process to start the snitch.py backend.
  ipcMain.handle("select-file", async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
      properties: ["openFile"],
    });
    if (canceled) return null;
    console.log("Accepted pcapng.. Checking for json existence...");
    setInterval(() => {
      if (!fileSent && fs.existsSync(filePath)) {
        // here we read the file in
        const data = fs.readFileSync(filePath, "utf8");
        mainWindow.webContents.send("json-data", data);
        fileSent = true; // Prevent sending multiple times
      }
    }, 3000);
    return filePaths[0];
  });
});
