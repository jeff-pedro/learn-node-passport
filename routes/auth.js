const crypto = require('crypto');

const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local');

const db = require('../db');

const router = express.Router();

passport.use(new LocalStrategy((username, password, cb) => {
    db.get('SELECT * FROM users WHERE username = ?', [ username ], (err, row) => {
        if (err) { return cb(err) };

        if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }) };

        crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', (err, hashedPassword) => {
            if (err) { return cb(err) };
        
            if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) { 
                return cb(null, false, { message: 'Incorrect username or password.' })
            };
            
            return cb(null, row);
        });
    });
}));

passport.serializeUser((user, cb) => {
    process.nextTick(() => {
        cb(null, { id: user.id, username: user.username });     
    });
});

passport.deserializeUser((user, cb) => {
    process.nextTick(() => {
        return cb(null, user);     
    });
});

router.get('/login', (req, res, next) => {
    res.render('login');
});

router.post('/login/password', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.post('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }

        res.redirect('/')
    });
});

router.get('/signup', (req, res, next) => {
    res.render('signup');
});

module.exports = router;
