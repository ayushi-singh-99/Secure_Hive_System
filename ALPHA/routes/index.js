const express = require('express')
const router = express.Router()
const { ensureGuest, ensureAuth } = require('../middleware/authChecker')
const File = require('../models/Files')
const User = require('../models/User')
const ROLE = require('../_helpers/role')
const { formatDate } = require("../_helpers/hbs");

// @desc    HomePage/ Landing Page
// @route   GET /
router.get('/', ensureGuest, (req, res) => {
    res.render('index', {title: 'Home'})
})

// @desc    Dashboard Page
// @route   GET /dashboard
router.get('/dashboard', ensureAuth, async (req, res) => {

    try {
        const files = await File.find({user: req.user.id}).lean()
        const user = await User.find({ user: req.params.id }).lean();
        // console.log(user)
        res.render('dashboard', {
            layout: './layouts/dashboard',
            title: 'Dashboard',
            name: req.user.name,
            formatDate,
            files,
            user,
            ROLE
        })

    } catch (err) {
        console.error(err);
        res.render('error/500')
    }

})

module.exports = router