const express = require('express');
const { exec } = require('child_process');
const app = express();

app.post('/compress', (req, res) => {
  const imgPath = req.body.image_path;
  exec('tar -czf archive.tar ' + imgPath, (err) => { // High risk cmd inject
    if (err) return res.send('Error');
    res.send('Compressed');
  });
});
