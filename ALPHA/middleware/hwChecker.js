const pbkdf2hw = require('../_helpers/pbkdf2')
const { formatDate } = require("../_helpers/hbs");
const User = require('../models/User')
const File = require('../models/Files')
const ROLE = require('../_helpers/role')

exports.hwChecker = async function(req, res, next) {

        try {

                const loginPass = req.body.password;
                const user = await User.findOne({ email: req.body.email })
                const dbcpassword = user.confirmpassword;
                const hwCompare = await pbkdf2hw.compare(dbcpassword, loginPass);

                if(hwCompare) {
                        const admin = await User.findOne({ role: 'Admin' });
                        const files = await File.find({ user: admin.id }).lean();
                        return res.render('dashboard', { 
                                layout: './layouts/dashboard',
                                title: 'Dashboard',
                                name: user.name, 
                                files, 
                                user, 
                                ROLE ,
                                formatDate
                        });
                } 

        } catch(err) {
                console.error(err);
        }

        return next();

}