const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const { Worker } = require("worker_threads");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const testcaseTempDir = path.join(os.tmpdir(), "testcases");
let mainWindow;
let selectedFilePath;
let isBackendLoaded = false;
let versionFilePath;
let isFirstRunAfterInstall = false;
let cachedOllamaInstalled = false;
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

const hostsJsonFilePath = path.join(testcaseTempDir, "hosts.json");
// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true });

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

function checkOllama() {
  return new Promise((resolve) => {
    exec("ollama --version", (execError) => {
      if (execError) {
        resolve(false); // not installed or not in PATH
      } else {
        resolve(true);
      }
    });
  });
}

function checkNewInstall() {
  if (!versionFilePath) return false;
  try {
    if (!fs.existsSync(versionFilePath)) {
      return true;
    }
    const storedVersion = fs.readFileSync(versionFilePath, "utf8").trim();
    return storedVersion !== app.getVersion();
  } catch (err) {
    console.error("Error checking install version:", err);
    return true;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1220,
    minHeight: 640,
    frame: false,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
      contextIsolation: true,
      nodeIntegration: true,
    },
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.setZoomFactor(0.6); // makes everything fit snuggly
  });
}

app.whenReady().then(() => {
  versionFilePath = path.join(app.getPath("userData"), "installed_version.txt");
  isFirstRunAfterInstall = checkNewInstall();
  checkOllama().then((isInstalled) => {
    cachedOllamaInstalled = isInstalled;
    if (!isInstalled) {
      console.log(
        "Ollama is not installed. LLM summarisation will be unavailable.",
      );
    }
    createWindow();
    app.on("activate", function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
    console.log("App ready, waiting for file selection...");
    // start the process that listens for the file selection and runs the backend command
    require("./back-comm");
    ipcMain.handle("select-file", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
      });
      if (canceled) return null;
      console.log("Accepted pcapng.. Checking for json existence...");
      isBackendLoaded = true;
      // Remove stale output directory so snitch always starts with a clean slate
      if (fs.existsSync(testcaseTempDir)) {
        fs.rmSync(testcaseTempDir, { recursive: true, force: true });
      }
      console.log("File selected:", filePaths[0]);
      selectedFilePath = filePaths[0];
      return filePaths[0];
    });
  });
});

ipcMain.handle("check-first-run", async () => {
  const isDev = !app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../..")
    : process.resourcesPath;
  const backendExe = platform === "win32" ? "snitch.exe" : "snitch";
  const filesToCheck = [
    {
      name: "PacketSnitch Backend (" + backendExe + ")",
      path: path.join(basePath, "backend", backendExe),
    },
    {
      name: "GeoIP Database (GeoLite2-City.mmdb)",
      path: path.join(basePath, "backend", "common", "GeoLite2-City.mmdb"),
    },
    {
      name: "MAC Vendors Database (mac-vendors-export.csv)",
      path: path.join(basePath, "backend", "common", "mac-vendors-export.csv"),
    },
    {
      name: "Services Database (service-names-port-numbers.csv)",
      path: path.join(
        basePath,
        "backend",
        "common",
        "service-names-port-numbers.csv",
      ),
    },
  ];
  const installedFiles = filesToCheck.map((f) => ({
    name: f.name,
    path: f.path,
    exists: fs.existsSync(f.path),
  }));
  return {
    isFirstRun: isFirstRunAfterInstall,
    version: app.getVersion(),
    ollamaInstalled: cachedOllamaInstalled,
    installedFiles,
  };
});

ipcMain.handle("dismiss-first-run", async () => {
  const currentVersion = app.getVersion();
  try {
    fs.writeFileSync(versionFilePath, currentVersion, "utf8");
    isFirstRunAfterInstall = false;
    return { success: true };
  } catch (err) {
    console.error("Failed to write version file:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("quit-app", () => {
  app.quit();
});

ipcMain.handle("save-json", async () => {
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save JSON Capture",
    defaultPath: path.join(app.getPath("documents"), "capture.json"),
    filters: [{ name: "JSON Files", extensions: ["json"] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  return new Promise((resolve) => {
    const workerPath = "./src/save-worker.js";
    const worker = new Worker(workerPath, {
      workerData: { srcPath: hostsJsonFilePath, destPath: filePath },
    });
    worker.on("message", (result) => {
      worker.terminate();
      resolve(result);
    });
    worker.on("error", (err) => {
      console.error("Save worker error:", err);
      worker.terminate();
      resolve({ success: false, error: err.message });
    });
  });
});

app.on("before-quit", () => {
  // make sure the backend snitch process dies!
  if (isBackendLoaded) {
    killBackendProcess();
  }
});
