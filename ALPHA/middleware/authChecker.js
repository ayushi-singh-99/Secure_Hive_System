const ROLE = require('../_helpers/role')

module.exports = {
    ensureAuth: function(req, res, next) {
        if(req.isAuthenticated()) {
            return next()
        } else {
            req.flash('error_msg', 'Please log in first!');
            res.redirect('/auth/login')
        }
    },
    ensureGuest: function(req, res, next) {
        if(req.isAuthenticated()) {
            res.redirect('/dashboard')
        } else {
            return next()
        }
    },
    ensureAdmin: function(req, res, next) {
        if(req.user.role === ROLE.ADMIN) {
            return next()
        } else {
            res.redirect('/dashboard')
        }
    },
}