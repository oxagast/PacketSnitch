const { workerData, parentPort } = require("worker_threads");
const fs = require("fs");

fs.copyFile(workerData.srcPath, workerData.destPath, (err) => {
  if (err) {
    parentPort.postMessage({ success: false, error: err.message });
  } else {
    parentPort.postMessage({ success: true });
  }
});
