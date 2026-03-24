const { ipcMain, app } = require("electron");
const { exec } = require("child_process");
const os = require("os");

const platform = os.platform();
const path = require("path");
ipcMain.handle("run-backend-command", async (event, filename) => {
  console.log(`Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../..")
    : process.resourcesPath;

  if (platform === "win32") {
    const appPath = basePath + "\\backend\\snitch.exe";
    //const appPath = app.getAppPath() + "\\resources\\backend\\snitch.exe";
    //  const appPathDev = app.getAppPath() + "\\backend\\snitch.exe";
    console.log(appPath);
    command = `"${appPath}" "${filename}" -a -o C:\\Windows\\Temp\\testcases`;
    //commandDev = `"${appPathDev}" "${filename}" -a -o C:\\Windows\\Temp\\testcases`;
  }
  if (platform === "linux") {
    const appPath = basePath + "/backend/snitch";
    console.log(appPath);
    //  command = `/usr/lib/packetsnitch/resources/backend/snitch "${filename}" -a -o /tmp/testcases`;
    command = `"${appPath}" "${filename}" -a -o /tmp/testcases`;
  }

  console.log("Command to run:", command);

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      //      if (error) return reject(error.message);
      //     if (stderr) return reject(stderr);
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
    });

    console.log("Backend started, watiting for JSON...");
  });

  /*
   return new Promise((resolve, reject) => {
    exec(commandDev, (error, stdout, stderr) => {
      //      if (error) return reject(error.message);
      //     if (stderr) return reject(stderr);
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
    });

    console.log("Backend started, watiting for JSON...");
  });
  */
});
