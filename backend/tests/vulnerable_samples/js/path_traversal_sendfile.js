const express = require('express');
const path = require('path');

const app = express();

app.get('/file', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: path traversal via sendFile
    res.sendFile(filename);
});
