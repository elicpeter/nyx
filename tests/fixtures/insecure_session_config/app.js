const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
  secret: 'my-hardcoded-secret',
  cookie: {
    httpOnly: false,
    secure: false,
    sameSite: 'none'
  }
}));

app.get('/', (req, res) => {
  res.send('Hello');
});
