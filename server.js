// server.js or app.js

const https = require('https');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const app = express();

// Read SSL certificate files
const options = {
    key: fs.readFileSync('path/to/private.key'),
    cert: fs.readFileSync('path/to/certificate.crt')
};

// Use HTTPS to create server
https.createServer(options, app).listen(443, () => {
    console.log('Server is running securely on HTTPS');
});

// Session setup with secure cookies
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true, // Ensures the cookie is only sent over HTTPS
        httpOnly: true, // Prevents JavaScript access to the cookie
        maxAge: 60000 // Cookie expiration time (in milliseconds)
    }
}));

// Your other middleware and routes go here...

module.exports = app;
