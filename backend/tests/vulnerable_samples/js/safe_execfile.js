const express = require('express');
const { execFile } = require('child_process');

const app = express();

app.get('/list', (req, res) => {
    const dir = req.query.dir;
    // SAFE: execFile does not invoke a shell, arguments are passed separately
    execFile('/usr/bin/ls', [dir], (error, stdout) => {
        res.send(stdout);
    });
});
