const session = require("express-session");

const config = {
    secret: "my-secret-key",
    password: "admin123",
    apiKey: "sk-1234567890abcdef",
};

function setupSession(app) {
    app.use(session({
        secret: config.secret,
        resave: false,
        saveUninitialized: true,
    }));
}
