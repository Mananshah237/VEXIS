const express = require('express');
const ejs = require('ejs');

const app = express();

app.get('/render', (req, res) => {
    const template = req.body.template;
    // VULNERABLE: SSTI via ejs.render with user-controlled template
    const html = ejs.render(template, { user: 'admin' });
    res.send(html);
});
