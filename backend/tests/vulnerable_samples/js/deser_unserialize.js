const express = require('express');
const serialize = require('node-serialize');

const app = express();

app.get('/profile', (req, res) => {
    const userData = req.cookies.profile;
    // VULNERABLE: insecure deserialization (node-serialize RCE)
    const obj = serialize.unserialize(userData);
    res.json(obj);
});
