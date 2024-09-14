httpdecoy.ts
import express from 'express';

const app = express();
const port: number = 8080;

app.get('/', (req, res) => {
  console.log('HTTP decoy accessed by', req.ip);
  res.send('<h1>This is a fake website decoy!</h1>');
});

app.listen(port, () => {
  console.log(`HTTP decoy service is running on port ${port}`);
});


