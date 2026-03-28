const express = require('express');

const app = express();

app.post('/proxy', async (req, res) => {
    const url = req.body.url;
    // VULNERABLE: SSRF via fetch with user-controlled URL
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});
