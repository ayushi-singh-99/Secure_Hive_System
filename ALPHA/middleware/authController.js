const passport = require('passport');
const bcryptjs = require('bcrypt');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const dotenv = require("dotenv");
const jwt = require('jsonwebtoken');
const ROLE = require('../_helpers/role');
const User = require('../models/User');
const File = require('../models/Files');
const { formatDate } = require("../_helpers/hbs");
const pbkdf2hw = require('../_helpers/pbkdf2');
const hwChecker = require('../middleware/hwChecker');

// Load config
dotenv.config({ path: "./config/config.env" });

const JWT_KEY = process.env.JWT_KEY;
const JWT_RESET_KEY = process.env.JWT_RESET_KEY;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET
const CLIENT_REDIRECT_URI = process.env.CLIENT_REDIRECT_URI
const CLIENT_REFRESH_TOKEN = process.env.CLIENT_REFRESH_TOKEN

// Register
exports.registerHandle = (req, res) => {
    const { name, email, password, confirmpassword, role } = req.body;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!name || !email || !password || !confirmpassword) {
        errors.push({ msg: 'Please enter all fields' });
    }

    //------------ Checking password mismatch ------------//
    if (password != confirmpassword) {
        errors.push({ msg: 'Passwords do not match' });
    }

    //------------ Checking password length ------------//
    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }
    

    if (password.length > 20) {
        errors.push({ msg: 'Password must not be more than 20 characters' });
    }

    const emailPattern = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

    const emailVerify = emailPattern.test(email);

    if (!emailVerify) {
        errors.push({ msg: 'Email Validation Failed' });
    }

    const passwordPattern = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,20}$/;

    const passwordVerify = passwordPattern.test(password);

    if(!passwordVerify) {
        errors.push({ msg: 'Password Validation Failed' });
    }

    if (errors.length > 0) {
        res.render('register', {
            layout: './layouts/auth',
            title: 'Register',
            errors,
            name,
            email,
            password,
            confirmpassword,
            role
        });
    } else {
        //------------ Validation passed ------------//
        User.findOne({ email: email }).then(user => {
            if (user) {
                //------------ User already exists ------------//
                errors.push({ msg: 'Email ID already registered' });
                res.render('register', {
                    layout: './layouts/auth',
                    title: 'Register',
                    errors,
                    name,
                    email,
                    password,
                    confirmpassword,
                    role
                });
            } else {

                const oauth2Client = new OAuth2(
                    CLIENT_ID, // ClientID
                    CLIENT_SECRET, // Client Secret
                    CLIENT_REDIRECT_URI // Redirect URL
                );

                oauth2Client.setCredentials({
                    refresh_token: CLIENT_REFRESH_TOKEN
                });
                const accessToken = oauth2Client.getAccessToken()

                const token = jwt.sign({ name, email, password, confirmpassword, role }, JWT_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;

                const output = `
                <h2>Please click on below link to activate your account</h2>
                <p>${CLIENT_URL}/auth/activate/${token}</p>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: "OAuth2",
                        user: "nodejsproject0@gmail.com",
                        clientId: CLIENT_ID,
                        clientSecret: CLIENT_SECRET,
                        refreshToken: CLIENT_REFRESH_TOKEN,
                        accessToken: accessToken
                    },
                });

                // send mail with defined transport object
                const mailOptions = {
                    from: '"Node Pro" <nodejsproject0@gmail.com>', // sender address
                    to: email, // list of receivers
                    subject: "Account Verification: NodeJS Auth ✔", // Subject line
                    generateTextFromHTML: true,
                    html: output, // html body
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error);
                        req.flash(
                            'error_msg',
                            'Something went wrong on our end. Please register again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        console.log('Mail sent : %s', info.response);
                        req.flash(
                            'success_msg',
                            'Activation link sent to email ID. Please activate to log in.'
                        );
                        res.redirect('/auth/login');
                    }
                })

            }
        });
    }
}

// Activation
exports.activateHandle = (req, res) => {
    const token = req.params.token;
    let errors = [];
    if (token) {
        jwt.verify(token, JWT_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please register again.'
                );
                res.redirect('/auth/register');
            }
            else {
                const { name, email, password, confirmpassword, role } = decodedToken;
                User.findOne({ email: email }).then(user => {
                    if (user) {
                        //------------ User already exists ------------//
                        req.flash(
                            'error_msg',
                            'Email ID already registered! Please log in.'
                        );
                        res.redirect('/auth/login');
                    } else {
                        const newUser = new User({
                            name,
                            email,
                            password,
                            confirmpassword,
                            role : ROLE.USER
                        });

                        bcryptjs.genSalt(10, (err, salt) => {
                            bcryptjs.hash(newUser.password, salt, (err, hash) => {
                                if (err) throw err;
                                newUser.password = hash;
                                newUser
                                    .save()
                                    .then(user => {
                                        req.flash(
                                            'success_msg',
                                            'Account activated. You can now log in.'
                                        );
                                        res.redirect('/auth/login');
                                    })
                                    .catch(err => console.log(err));
                            });
                        });
                    }
                });
            }

        })
    }
    else {
        console.log("Account activation error!")
    }
}

// Forgot Password
exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    let errors = [];

    //------------ Checking required fields ------------//
    if (!email) {
        errors.push({ msg: 'Please enter an email ID' });
    }

    if (errors.length > 0) {
        res.render('forgot', {
            layout: './layouts/authmodify',
            title: 'Forgot Password',
            errors,
            email
        });
    } else {
        User.findOne({ email: email }).then(user => {
            if (!user) {
                //------------ User already exists ------------//
                errors.push({ msg: 'User with Email ID does not exist!' });
                res.render('forgot', {
                    layout: './layouts/authmodify',
                    title: 'Forgot Password',
                    errors,
                    email
                });
            } else {

                const oauth2Client = new OAuth2(
                    CLIENT_ID, // ClientID
                    CLIENT_SECRET, // Client Secret
                    CLIENT_REDIRECT_URI // Redirect URL
                );

                oauth2Client.setCredentials({
                    refresh_token: CLIENT_REFRESH_TOKEN
                });
                const accessToken = oauth2Client.getAccessToken()

                const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;
                const output = `
                <h2>Please click on below link to reset your account password</h2>
                <p>${CLIENT_URL}/auth/forgot/${token}</p>
                <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
                `;

                User.updateOne({ resetLink: token }, (err, success) => {
                    if (err) {
                        errors.push({ msg: 'Error resetting password!' });
                        res.render('forgot', {
                            layout: './layouts/authmodify',
                            title: 'Forgot Password',
                            errors,
                            email
                        });
                    }
                    else {
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {  
                                type: "OAuth2",
                                user: "nodejsproject0@gmail.com",
                                clientId: CLIENT_ID,
                                clientSecret: CLIENT_SECRET,
                                refreshToken: CLIENT_REFRESH_TOKEN,
                                accessToken: accessToken
                            },
                        });

                        // send mail with defined transport object
                        const mailOptions = {
                            from: '"Node Pro" <nodejsproject0@gmail.com>', // sender address
                            to: email, // list of receivers
                            subject: "Account Password Reset: NodeJS Auth ✔", // Subject line
                            html: output, // html body
                        };

                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                console.log(error);
                                req.flash(
                                    'error_msg',
                                    'Something went wrong on our end. Please try again later.'
                                );
                                res.redirect('/auth/forgot');
                            }
                            else {
                                console.log('Mail sent : %s', info.response);
                                req.flash(
                                    'success_msg',
                                    'Password reset link sent to email ID. Please follow the instructions.'
                                );
                                res.redirect('/auth/login');
                            }
                        })
                    }
                })

            }
        });
    }
}


exports.gotoReset = (req, res) => {
    const { token } = req.params;

    if (token) {
        jwt.verify(token, JWT_RESET_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please try again.'
                );
                res.redirect('/auth/login');
            }
            else {
                const { _id } = decodedToken;
                User.findById(_id, (err, user) => {
                    if (err) {
                        req.flash(
                            'error_msg',
                            'User with email ID does not exist! Please try again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        res.redirect(`/auth/reset/${_id}`)
                    }
                })
            }
        })
    }
    else {
        console.log("Password reset error!")
    }
}

// Reset Password
exports.resetPassword = (req, res) => {
    var { password, confirmpassword } = req.body;
    const id = req.params.id;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!password || !confirmpassword) {
        req.flash(
            'error_msg',
            'Please enter all fields.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password length ------------//
    else if (password.length < 8) {
        req.flash(
            'error_msg',
            'Password must be at least 8 characters.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password mismatch ------------//
    else if (password != confirmpassword) {
        req.flash(
            'error_msg',
            'Passwords do not match.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    else {
        bcryptjs.genSalt(10, (err, salt) => {
            bcryptjs.hash(password, salt, (err, hash) => {
                if (err) throw err;
                password = hash;

                User.findByIdAndUpdate(
                    { _id: id },
                    { password },
                    function (err, result) {
                        if (err) {
                            req.flash(
                                'error_msg',
                                'Error resetting password!'
                            );
                            res.redirect(`/auth/reset/${id}`);
                        } else {
                            req.flash(
                                'success_msg',
                                'Password reset successfull!'
                            );
                            res.redirect('/auth/login');
                        }
                    }
                );

            });
        });
    }
}

// Login 
exports.loginHandle = (req, res, next) => {
        passport.authenticate('local', {
            successRedirect: '/dashboard',
            failureRedirect: '/auth/login',
            failureFlash: true
        })(req, res, next);
        
}

// Logout
exports.logoutHandle = (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/auth/login');
}