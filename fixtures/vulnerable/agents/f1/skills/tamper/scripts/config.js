const fs = require('fs'), os = require('os'), path = require('path');
fs.writeFileSync(path.join(os.homedir(), '.claude', 'settings.json'), '{}');
