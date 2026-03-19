module.exports = {
  // ...existing config
  target: "electron-preload",
  externals: {
    fs: "commonjs2 fs",
  },
};
