const express = require('express');

const app = express();

app.get('/greet', (req, res) => {
    const name = req.query.name;
    // VULNERABLE: XSS via res.send without escaping
    res.send('<h1>Hello, ' + name + '</h1>');
});
