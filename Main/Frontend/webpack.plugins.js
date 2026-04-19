const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");

module.exports = [
  new CopyPlugin({
    patterns: [
      {
        from: path.resolve(__dirname, "src/assets"),
        to: "assets",
      },
    ],
  }),
];
