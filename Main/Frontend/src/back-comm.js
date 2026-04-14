const { BrowserWindow, ipcMain, app, ipcRenderer } = require("electron");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const path = require("path");
const fs = require("fs");
systemTempDir = os.tmpdir();
testcaseOutputDir = path.join(systemTempDir, "testcases");
ipcMain.handle("run-backend-command", async (event, filename, useLLM) => {
  console.log(`Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../..")
    : process.resourcesPath;
  let snitchExePath;

  if (platform === "win32") {
    snitchExePath = path.join(basePath, "\\backend\\snitch.exe");
  }
  if (platform === "linux") {
    snitchExePath = path.join(basePath, "/backend/snitch");
  } else {
    snitchExePath = path.join(basePath, "\\backend\\snitch.exe");
  }

  backendCommand = `"${snitchExePath}" "${filename}" -a -o "${testcaseOutputDir}"${useLLM ? "" : " --nollm"}`;

  // Always start with a clean output directory so snitch never hits the
  // interactive overwrite prompt on second (and later) runs.
  if (fs.existsSync(testcaseOutputDir)) {
    fs.rmSync(testcaseOutputDir, { recursive: true, force: true });
  }

  console.log("Command to run:", backendCommand);

  function sendError(message) {
    const mainWin = BrowserWindow.getAllWindows()[0]; // or track your main window
    if (mainWin) {
      mainWin.webContents.send("backend-error", message);
    }
  }

  return new Promise((resolve, reject) => {
    exec(backendCommand, (error, stdout, stderr) => {
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
      if (stdout.includes("Ollama")) {
        sendError("Backend LLM generation error!");
      }
      if (error) {
        if (stderr.includes("supported capture file")) {
          sendError("Unsupported file format!");
        } else {
          sendError("Backend execution error! " + error);
        }
      }
    });

    console.log("Backend started, watiting for JSON...");
  });
});
