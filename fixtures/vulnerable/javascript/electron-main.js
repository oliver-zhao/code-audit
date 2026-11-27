// Electron and GraphQL seeds.
const { app, BrowserWindow, shell } = require("electron");
const { ApolloServer } = require("apollo-server");

function createWindow(link) {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      nodeIntegrationInSubFrames: true,
    },
  });
  win.webContents.on("will-navigate", () => shell.openExternal(link));
  return win;
}

const server = new ApolloServer({ typeDefs: "type Query { ok: Boolean }", introspection: true });

app.whenReady().then(() => createWindow("https://example.invalid"));
module.exports = { server };
