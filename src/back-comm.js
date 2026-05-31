const { BrowserWindow, ipcMain } = require("electron");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const path = require("path");
const fs = require("fs");
const systemTempDir = os.tmpdir();
const testcaseOutputDir = path.join(systemTempDir, "testcases");
ipcMain.handle("run-backend-command", async (event, filename, useLLM) => {
  global.logBackend(`[Bridge] Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../../src/")
    : process.resourcesPath;
  let snitchExePath;

  if (platform === "win32") {
    snitchExePath = path.join(basePath, "\\backend\\snitch\\snitch.exe");
  } else if (platform === "linux") {
    snitchExePath = path.join(basePath, "/backend/snitch/snitch");
  } else {
    snitchExePath = path.join(basePath, "/backend/snitch/snitch");
  }

  const backendCommand = `"${snitchExePath}" "${filename}" -v -a -o "${testcaseOutputDir}"${useLLM ? "" : " --nollm"}`;

  // Always start with a clean output directory so snitch never hits the
  // interactive overwrite prompt on second (and later) runs.
  if (fs.existsSync(testcaseOutputDir)) {
    fs.rmSync(testcaseOutputDir, { recursive: true, force: true });
  }

  global.logBackend("[Bridge] Exec: ", backendCommand);

  function sendError(message) {
    const mainWin = BrowserWindow.getAllWindows()[0]; // or track your main window
    if (mainWin) {
      mainWin.webContents.send("backend-error", message);
    }
  }

  return new Promise((resolve) => {
    exec(
      backendCommand,
      { maxBuffer: 1024 * 1024 * 50 },
      (error, stdout, stderr) => {
        resolve(stdout);
        global.logBackend("", stdout);
        global.logBackend("", stderr);
        if (stdout.includes("Ollama")) {
          sendError("[Bridge] Backend LLM generation error!");
        }
        if (error) {
          if (stderr.includes("supported capture file")) {
            sendError("[Bridge] Unsupported file format!");
          } else {
            sendError("[Bridge] Backend execution error! " + error);
          }
        } else {
          setTimeout(() => {
            const hostsJsonPath = path.join(testcaseOutputDir, "hosts.json");
            const mainWin = BrowserWindow.getAllWindows()[0];
            if (mainWin && fs.existsSync(hostsJsonPath)) {
              const hostsJsonData = fs.readFileSync(hostsJsonPath, "utf8");
              mainWin.webContents.send("json-data", hostsJsonData);
            }
          }, 200);
        }
      },
    );

    global.logBackend("[Bridge] Backend packet processing initiated");
  });
});
