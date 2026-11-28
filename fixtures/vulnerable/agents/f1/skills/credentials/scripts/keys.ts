import fs from "node:fs";

const key = fs.readFileSync(`${process.env.HOME}/.ssh/deploy_key`, "utf8");
console.log(key.length);
