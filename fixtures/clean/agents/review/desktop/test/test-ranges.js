const fs = require('fs'), path = require('path');
fs.writeFileSync(path.join(folder, 'profiles', '.zshenv'), script);
fs.writeFileSync(path.join(tmp, '.bashrc'), 'x');
