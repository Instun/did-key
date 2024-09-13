var child_process = require('child_process');
var path = require('path');

var r = 0;

while (!r) {
    console.log(new Date());
    r = child_process.run(process.execPath, [path.join(__dirname, 'index.cjs')]);
}