const { ipcMain } = require("electron");
const { exec } = require("child_process");

ipcMain.handle("run-backend-command", async (event, filename) => {
  const command = `python3 backend/snitch.py "${filename}"`;
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) return reject(error.message);
      if (stderr) return reject(stderr);
      resolve(stdout);
    });
  });
});
