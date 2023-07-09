const crypto = require('crypto');

const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local');

const db = require('../db');

const router = express.Router();

router.get('/login', (req, res, next) => {
    res.render('login');
});

module.exports = router;
