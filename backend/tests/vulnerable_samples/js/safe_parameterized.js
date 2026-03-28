const express = require('express');
const mysql = require('mysql');

const app = express();
const connection = mysql.createConnection({ host: 'localhost', database: 'mydb' });

app.get('/user/:id', (req, res) => {
    const id = req.params.id;
    // SAFE: parameterized query with ? placeholder
    connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        res.json(results);
    });
});
