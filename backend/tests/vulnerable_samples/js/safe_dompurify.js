const express = require('express');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const app = express();

app.get('/display', (req, res) => {
    const input = req.query.input;
    const window = new JSDOM('').window;
    const DOMPurify = createDOMPurify(window);
    // SAFE: DOMPurify sanitizes XSS payloads; res.json() JSON-encodes (no raw HTML)
    const clean = DOMPurify.sanitize(input);
    res.json({ content: clean });
});
