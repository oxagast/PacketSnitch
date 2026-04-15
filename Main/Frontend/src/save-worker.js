const { workerData, parentPort } = require("worker_threads");
const fs = require("fs");

fs.writeFile(workerData.filePath, workerData.jsonData, "utf8", (err) => {
  if (err) {
    parentPort.postMessage({ success: false, error: err.message });
  } else {
    parentPort.postMessage({ success: true });
  }
});
