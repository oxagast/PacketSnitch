const { FusesPlugin } = require("@electron-forge/plugin-fuses");
const { FuseV1Options, FuseVersion } = require("@electron/fuses");
const path = require("path");
module.exports = {
  packagerConfig: {
    asar: true,
    extraResource: ["src/backend/"],
    icon: "ps-icon",
    setupIcon: path.resolve(__dirname, "ps-installer-icon.ico"),
  },
  rebuildConfig: {},
  makers: [
    {
      name: "@electron-forge/maker-squirrel",
      config: {
        loadingGif: path.resolve(__dirname, "ps-install-loop.gif"),
        iconUrl: path.resolve(__dirname, "ps-icon.ico"),
        setupIcon: path.resolve(__dirname, "ps-installer-icon.ico"),
        name: "PacketSnitch",
        setupExe: "PacketSnitchInstaller.exe",
        vendor: "oxasploits, llc",
        authors: "Marshall Whittaker",
        copyright: "Copyright (c) 2026 oxasploits, llc",
        primaryIcon: path.resolve(__dirname, "ps-icon.ico"),
        productName: "PacketSnitch",
        description:
          "A network traffic analysis tool, designed to help users understand and monitor network activity on their devices.",
      },
    },
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin"],
    },
    {
      name: "@electron-forge/maker-deb",
      config: {
        primaryIcon: path.resolve(__dirname, "ps-icon.png"),
        authors: "Marshall Whittaker",
        copyright: "Copyright (c) 2026 oxasploits, llc",
        productName: "PacketSnitch",
        description:
          "A network traffic analysis tool, designed to help users understand and monitor network activity on their devices.",
        homepage: "https://github.com/oxasploits/PacketSnitch",
        maintainer: "Marshall Whittaker <marshall@oxasploits.com>",
        categories: ["Utility", "Network"],
        vendor: "oxasploits, llc",
      },
    },
    {
      name: "@electron-forge/maker-rpm",
      config: {
        options: {
          name: "packetsnitch",
          primaryIcon: path.resolve(__dirname, "ps-icon.png"),
          authors: "oxasploits, llc",
          copyright: "Copyright (c) 2026 oxasploits, llc",
          productName: "PacketSnitch",
          description:
            "A network traffic analysis tool, designed to help users understand and monitor network activity on their devices.",
          homepage: "https://github.com/oxasploits/PacketSnitch",
          maintainer: "Marshall Whittaker <marshall@oxasploits.com>",
          categories: ["Utility", "Network"],
          vendor: "oxasploits, llc",
        },
      },
    },
  ],
  plugins: [
    {
      name: "@electron-forge/plugin-auto-unpack-natives",
      config: {},
    },
    {
      name: "@electron-forge/plugin-webpack",
      config: {
        mainConfig: "./webpack.main.config.js",
        renderer: {
          config: "./webpack.renderer.config.js",
          entryPoints: [
            {
              html: "./src/index.html",
              js: "./src/renderer.js",
              name: "main_window",
              preload: {
                js: "./src/preload.js",
              },
            },
          ],
        },
      },
    },
    // Fuses are used to enable/disable various Electron functionality
    // at package time, before code signing the application
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
    }),
  ],
};
