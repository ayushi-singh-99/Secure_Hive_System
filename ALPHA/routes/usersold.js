const express = require('express')
const router = express.Router()
const passport = require('passport')
const { ensureAuth, ensureGuest } = require('../middleware/auth')
const User = require('../models/User')
const File = require('../models/Files')
const { formatDate } = require("../_helpers/hbs");
const bcrypt = require("bcrypt")
const hwChecker = require('../middleware/hwChecker')
const ROLE = require('../_helpers/role')

// @desc    Login/Sign-In Page
// @route   GET /users/login
router.get('/login', ensureGuest, (req, res) => {
    res.render('login', {
        layout: './layouts/auth',
        title: 'Login',
    })
})

// @desc    Registration Page
// @route   GET /users/register
router.get('/register', ensureGuest, (req, res) => {
    res.render('register', {
        layout: './layouts/auth',
        title: 'Register',
    })
})

// @desc    Forgot Page
// @route   GET /users/forgot
router.get('/forgot', (req, res) => {
    res.render('forgot', {
        layout: './layouts/authmodify',
        title: 'Forgot Password',
    })
})

// @desc    Forgot Page
// @route   GET /users/reset
router.get('/reset', (req, res) => {
    res.render('reset', {
        layout: './layouts/authmodify',
        title: 'Reset Password',
    })
})



// @desc    Logout
// @route   GET /users/logout
router.get('/logout', ensureAuth, (req, res, next) => {
    req.logout();
    res.redirect('login');
});

// @desc    Dashboard
// @route   GET /users/dashboard
router.get('/dashboard', ensureAuth, async (req, res) => {

    try {
        const files = await File.find({user: req.user.id}).lean()

        res.render('dashboard', {
            layout: './layouts/dashboard',
            title: 'Dashboard',
            name: req.user.name,
            formatDate,
            files
        })

    } catch (error) {
        console.error(err);
        res.render('error/500')
    }

})


// @desc    Login/Sign-In Page
// @route   POST /users/login
router.post('/login', passport.authenticate('local', {
    successRedirect: 'dashboard',
    failureRedirect: '/users/login'
}))


// @desc    Register/Sign-Up Page
// @route   POST /users/register
router.post('/register', async (req, res) => {

    try {

        const email = req.body.email;
        const password = req.body.password;
        const confirmpassword = req.body.confirmpassword;

        const emailPattern = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

        const emailVerify = emailPattern.test(email);

        const passwordPattern = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{6,12}$/;

        const passwordVerify = passwordPattern.test(password);

        if(!emailVerify) {
            res.send("Email Validation Failed")
        }
        
        if(!passwordVerify) {
            res.send("Password Validation Failed")
        }

        if(emailVerify && passwordVerify && password === confirmpassword) {

            const registerUser = new User({
                name : req.body.name,
                email : req.body.email,
                password : password,
                confirmpassword : confirmpassword,
                role: ROLE.USER
            })
    
            const registered = await registerUser.save();
            res.redirect('login');

        } else {
            res.send("Passwords are not matching");
        }
        
    } catch (err) {
        console.log(err);
        res.send(err);
    }

})

//------------ Email ACTIVATE Handle ------------//
router.get('/activate/:token');

//------------ Forgot Password Handle ------------//
router.post('/forgot');

//------------ Reset Password Handle ------------//
router.post('/reset/:id');

//------------ Reset Password Handle ------------//
router.get('/forgot/:token');

module.exports = router