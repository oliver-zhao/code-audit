// Safe Electron and GraphQL counterparts.
const { app, BrowserWindow, shell } = require("electron");
const { ApolloServer } = require("apollo-server");
const path = require("path");

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });
  win.webContents.on("will-navigate", () => shell.openExternal("https://example.invalid/help"));
  return win;
}

const server = new ApolloServer({ typeDefs: "type Query { ok: Boolean }", introspection: process.env.NODE_ENV !== "production" });

app.whenReady().then(() => createWindow());
module.exports = { server };
