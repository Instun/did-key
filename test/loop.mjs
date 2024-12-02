import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

var r = 0;

while (!r) {
    console.log(new Date());
    r = spawn(process.execPath, [join(__dirname, 'index.mjs')], { stdio: 'inherit' });
}
