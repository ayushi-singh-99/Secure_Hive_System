const express = require('express')
const router = express.Router()
const { ensureAdmin, ensureAuth } = require('../middleware/authChecker')
const connectDB = require('../config/db')
const User = require('../models/User')
const File = require('../models/Files')
const { formatDate } = require("../_helpers/hbs");
const ROLE = require('../_helpers/role')

// @desc    Show admin dashboard
// @route   GET /admin/admindash
router.get('/admindash', ensureAuth, ensureAdmin, async (req, res) => {
    
    try {

        const users = await User.find({ user: req.params.id }).lean();
        res.render('admin/admindash', {
            layout: './layouts/dashboard',
            title: 'Admin Dashboard',
            users,
            formatDate,
            ROLE
        })

    } catch (err) {
        console.error(err);
        res.render('error/500')
    }
})


// @desc    Delete User
// @route   DELETE /admin/admindash/:id
router.delete('/admindash/:id', ensureAuth, ensureAdmin, async (req, res) => {
    
    try {

        if(await User.deleteOne({ _id: req.params.id })) {
            req.flash(
                'success_msg',
                'User Deleted Successfully'
            );
            res.redirect('/admin/admindash')    
        } else {
            req.flash(
                'error_msg',
                'Failed to delete the file'
            );
        }
                
    } catch (err) {
        console.error(err)
        return res.render('error/500')
    }
})

// @desc    Show fake dashboard
// @route   GET /admin/dash
router.get('/dash', ensureAuth, async (req, res) => {
    
    try {

        const files = await File.find({user: req.user.id }).lean()

        res.render('admin/dash', {
            layout: './layouts/dashboard',
            title: 'Dashboard',
            formatDate,
            files
        })

    } catch (err) {
        console.error(err);
        res.render('error/500')
    }
})

// @desc    Logout
// @route   GET /admin/logout
router.get('/logout', ensureAuth, ensureAdmin, (req, res, next) => {
    req.logout();
    res.redirect('login');
});

module.exports = router