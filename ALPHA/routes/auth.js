const express = require('express');
const router = express.Router();
const { ensureGuest, ensureAuth } = require('../middleware/authChecker')
const { hwChecker } = require("../middleware/hwChecker");


//------------ Importing Controllers ------------//
const authController = require('../middleware/authController')

//------------ Login Route ------------//
router.get('/login', ensureGuest, (req, res) => res.render('login', {
        layout: './layouts/auth',
        title: 'Login',
    })
);

//------------ Forgot Password Route ------------//
router.get('/forgot', ensureGuest, (req, res) => res.render('forgot', {
    layout: "./layouts/authmodify",
    title: "Forgot Password"
}));

//------------ Reset Password Route ------------//
// /:id
router.get('/reset/:id', ensureGuest, (req, res) => {
    res.render('reset', { 
        layout: "./layouts/authmodify",
        title: "Reset Password",
        id: req.params.id
    })
});

//------------ Register Route ------------//
router.get('/register', ensureGuest, (req, res) => res.render('register', {
        layout: './layouts/auth',
        title: 'Register',
    })
);

//------------ Register POST Handle ------------//
router.post('/register', authController.registerHandle);

//------------ Email ACTIVATE Handle ------------//
router.get('/activate/:token', authController.activateHandle);

//------------ Forgot Password Handle ------------//, 
router.post('/forgot', authController.forgotPassword);

//------------ Reset Password Handle ------------//
router.post('/reset/:id', authController.resetPassword);

//------------ Reset Password Handle ------------//
router.get('/forgot/:token', authController.gotoReset);

//------------ Login POST Handle ------------//
router.post('/login', hwChecker, authController.loginHandle);

//------------ Logout GET Handle ------------//
router.get('/logout', ensureAuth, authController.logoutHandle);

module.exports = router;