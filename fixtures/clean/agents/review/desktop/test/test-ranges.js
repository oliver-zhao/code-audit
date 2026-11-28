const fs = require('fs'), path = require('path');
fs.writeFileSync(path.join(folder, 'profiles', '.zshenv'), script);
fs.writeFileSync(path.join(tmp, '.bashrc'), 'x');
const env = { ENV: path.join(folder, 'startup'), ZDOTDIR: path.join(folder, 'profiles') };
