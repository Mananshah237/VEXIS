const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    // VULNERABLE: command injection via exec
    exec('ping -c 1 ' + host, (error, stdout) => {
        res.send(stdout);
    });
});
