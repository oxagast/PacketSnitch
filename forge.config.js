const { FusesPlugin } = require("@electron-forge/plugin-fuses");
const { FuseV1Options, FuseVersion } = require("@electron/fuses");
const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");
const desc =
  "A network traffic analysis tool, designed to help users understand and monitor network activity on their devices.";

module.exports = {
  packagerConfig: {
    icon: path.join(__dirname, "logo", "ps-icon"),
    asar: true,
    extraResource: ["src/backend/snitch", "src/backend/common/"],
  },
  // The following bin compression works, but it significantly increases the time the binary
  // takes to load, while not reducing the file size of the installers much becaseu they are
  // already compressed by NSIS and DEB/RPM packaging. For now, it's better to have faster
  // load times than slightly larger installers.  Maybe we can revisit this later.
/*   hooks: {
    async postPackage(config, options) {
      const outputPath = options.outputPaths[0];
      let executablePath;
      if (options.platform === "win32") {
        executablePath = path.join(
          outputPath,
          `${options.executableName || "packetsnitch"}.exe`,
        );
      } else if (options.platform === "linux") {
        executablePath = path.join(
          outputPath,
          options.executableName || "packetsnitch",
        );
      } else {
        console.log(`Skipping UPX for platform ${options.platform}`);
        return;
      }
      if (!fs.existsSync(executablePath)) {
        throw new Error(`Executable not found: ${executablePath}`);
      }
      execSync("upx -q -4 " + executablePath, {
        stdio: "ignore",
      });
      console.log("UPX compression complete.");
    },
  }, */
  rebuildConfig: {},
  makers: [
    {
      name: "@electron-forge/maker-squirrel",
      config: {
        loadingGif: path.resolve(__dirname, "logo/ps-install-loop.gif"),
        iconUrl:
          "https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-icon.ico",
        setupIcon: path.resolve(__dirname, "logo/ps-installer-icon.ico"),
        name: "PacketSnitch",
        setupExe: "PacketSnitchInstaller.exe",
        vendor: "oxasploits, llc",
        authors: "Marshall Whittaker",
        copyright: "Copyright (c) 2026 oxasploits, llc",
        primaryIcon: path.resolve(__dirname, "logo/ps-icon.ico"),
        productName: "PacketSnitch",
        description: desc,
      },
    },
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin"],
    },
    {
      name: "@electron-forge/maker-deb",
      config: {
        primaryIcon: path.resolve(__dirname, "logo/ps-icon.png"),
        name: "packetsnitch",
        authors: "Marshall Whittaker",
        copyright: "Copyright (c) 2026 oxasploits, llc",
        productName: "PacketSnitch",
        description: desc,
        homepage: "https://github.com/oxasploits/PacketSnitch",
        maintainer: "Marshall Whittaker <marshall@oxasploits.com>",
        categories: [
          "Utility",
          "Network",
          "kali-network-information",
          "kali-network-service-discovery",
          "kali-network-sniffing",
        ],

        vendor: "oxasploits, llc",
        icon: path.resolve(__dirname, "logo/ps-icon-rounded.png"),
        desktopTemplate: path.resolve(__dirname, "desktop.ejs"),
      },
    },
    {
      name: "@electron-forge/maker-rpm",
      config: {
        options: {
          name: "packetsnitch",
          authors: "oxasploits, llc",
          copyright: "Copyright (c) 2026 oxasploits, llc",
          productName: "PacketSnitch",
          description: desc,
          homepage: "https://github.com/oxasploits/PacketSnitch",
          maintainer: "Marshall Whittaker <marshall@oxasploits.com>",
          categories: ["Utility", "Network"],
          vendor: "oxasploits, llc",
          icon: path.resolve(__dirname, "logo/ps-icon-rounded.png"),
          desktopTemplate: path.join(__dirname, "desktop.ejs"),
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
