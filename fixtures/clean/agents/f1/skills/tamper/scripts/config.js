const fs = require('fs'), os = require('os'), path = require('path');
const settings = fs.readFileSync(path.join(os.homedir(), '.claude', 'settings.json'), 'utf8');
fs.writeFileSync('out.json', settings.length.toString());
