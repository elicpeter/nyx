import express from 'express';
import session from 'express-session';

const app = express();

app.use(session({
    secret: 'keyboard cat',
    cookie: {
        httpOnly: false,
        secure: true,
    },
}));
