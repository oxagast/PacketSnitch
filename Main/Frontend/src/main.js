const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const testcaseTempDir = path.join(os.tmpdir(), "testcases");
let mainWindow;
let selectedFilePath;
let isBackendLoaded = false;
if (require("electron-squirrel-startup")) {
  app.quit();
}

ipcMain.handle("file-size", async () => {
  try {
    // Get file stats asynchronously
    const fileStats = await fs.promises.stat(selectedFilePath); // Using promises version of stat
    return fileStats.size; // Send back the file size
  } catch (fileError) {
    console.error("Error getting file stats:", fileError);
    return 0; // Return 0 if there's an error
  }
});

hostsJsonFilePath = path.join(testcaseTempDir, "hosts.json");
// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true }, (fileError) => {
  if (fileError) console.error(fileError);
});

function killBackendProcess() {
  console.log("Killing backend proc...");
  if (platform === "win32") {
    exec("taskkill /IM snitch.exe /T /F", (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "testcases"', (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
}

function killProcess() {
  console.log("Killing backend proc...");
  if (platform === "win32") {
    exec("taskkill /IM packetsnitch.exe /T /F", (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "packetsnitch"', (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
}

checkOllama().then((isInstalled) => {
  if (isInstalled) {
    console.log("Ollama is installed, proceeding with app launch...");
  } else {
    console.log(
      "Ollama is not installed. LLM summarisation will be unavailable.",
    );
  }
});

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1180,
    minHeight: 600,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
    contextIsolation: true,
    nodeIntegration: true,
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.setZoomFactor(0.7); // makes everything fit snuggly
  });
}

app.whenReady().then(() => {
  checkOllama().then((isInstalled) => {
    createWindow();
    app.on("activate", function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
    console.log("App ready, waiting for file selection...");
    let isFileSent = false;
    // start the process that listens for the file selection and runs the backend command
    require("./back-comm");
    ipcMain.handle("select-file", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
      });
      if (canceled) return null;
      console.log("Accepted pcapng.. Checking for json existence...");
      isBackendLoaded = true;
      isFileSent = false; // Reset so new JSON data will be sent for each load
      // Remove stale output directory so snitch always starts with a clean slate
      if (fs.existsSync(testcaseTempDir)) {
        fs.rmSync(testcaseTempDir, { recursive: true, force: true });
      }
      setInterval(() => {
        if (!isFileSent && fs.existsSync(hostsJsonFilePath)) {
          // here we read the file in
          const hostsJsonData = fs.readFileSync(hostsJsonFilePath, "utf8");
          mainWindow.webContents.send("json-data", hostsJsonData);

          isFileSent = true; // Prevent sending multiple times
        }
      }, 1000);
      console.log("File selected:", filePaths[0]);
      selectedFilePath = filePaths[0];
      return filePaths[0];
    });
  });
});

function checkOllama() {
  return new Promise((resolve) => {
    exec("ollama --version", (fileError, stdout, stderr) => {
      if (fileError) {
        resolve(false); // not installed or not in PATH
      } else {
        resolve(true);
      }
    });
  });
}

app.on("before-quit", () => {
  // make sure the backend snitch process dies!
  if (isBackendLoaded) {
    killBackendProcess();
  }
});
