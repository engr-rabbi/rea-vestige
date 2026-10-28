/**
 * JavaScript/Electron fixture project with known ground truth for the
 * JS provider: imports, exports, IPC channels, routes, manifest facts.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export const JS_GROUND_TRUTH = {
  packageJson: {
    name: "vestige-sample-app",
    version: "1.2.3",
    main: "main.js",
    dependencies: { electron: "31.0.0", express: "4.19.0" },
    devDependencies: { typescript: "^5.0.0" },
  },
  mainJs: {
    imports: ["electron", "node:path", "./renderer-bridge.js"],
    exports: [],
    ipcMainChannels: ["app:read-config", "app:write-config", "app:compute"],
    routes: [] as Array<{ method: string; path: string }>,
  },
  serverJs: {
    imports: ["express"],
    routes: [
      { method: "GET", path: "/health" },
      { method: "POST", path: "/api/items" },
      { method: "DELETE", path: "/api/items/:id" },
    ],
  },
  rendererJs: {
    imports: [],
    exports: ["bridge"],
    ipcRendererChannels: ["app:read-config", "app:compute", "ui:refresh"],
  },
} as const;

export const buildJsProject = (rootDir: string): string => {
  mkdirSync(rootDir, { recursive: true });
  mkdirSync(path.join(rootDir, "lib"), { recursive: true });

  writeFileSync(
    path.join(rootDir, "package.json"),
    JSON.stringify(JS_GROUND_TRUTH.packageJson, null, 2),
  );

  writeFileSync(
    path.join(rootDir, "main.js"),
    `const { app, ipcMain } = require("electron");
const path = require("node:path");
const { registerBridge } = require("./renderer-bridge.js");

ipcMain.handle("app:read-config", () => ({ ok: true }));
ipcMain.on("app:write-config", (event, payload) => {
  event.returnValue = "stored";
});
ipcMain.once("app:compute", (event, n) => {
  event.returnValue = n * 2;
});

app.whenReady().then(() => {
  registerBridge();
});
`,
  );

  writeFileSync(
    path.join(rootDir, "lib", "server.js"),
    `import express from "express";

const app = express();

app.get("/health", (req, res) => res.json({ status: "ok" }));
app.post("/api/items", (req, res) => res.status(201).json(req.body));
app.delete("/api/items/:id", (req, res) => res.sendStatus(204));

export default app;
`,
  );

  writeFileSync(
    path.join(rootDir, "lib", "renderer-bridge.js"),
    `import { ipcRenderer } from "electron";

const readConfig = async () => ipcRenderer.invoke("app:read-config");
const compute = (n) => ipcRenderer.sendSync("app:compute", n);
ipcRenderer.on("ui:refresh", () => {});

export const bridge = { readConfig, compute };
`,
  );

  return rootDir;
};
