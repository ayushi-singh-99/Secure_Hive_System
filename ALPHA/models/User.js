const mongoose =require("mongoose");
const bcrypt = require("bcrypt");
const pbkdf2hw = require('../_helpers/pbkdf2');
const ROLE = require("../_helpers/role")

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required:true
    },
    email: {
        type: String,
        required:true,
        unique:true
    },
    password: {
        type: String,
        required:true
    },
    confirmpassword: {
        type: String,
        required:true
    },
    role: {
        type: String,
        required: true
    },
    verified: {
        type: Boolean,
        default: false
    },
    resetLink: {
        type: String,
        default: ''
    },
}, { timestamps: true })

//Hashing the password
UserSchema.pre("save", async function(next) {
    if(this.isModified("password")) {

        const pw = "honeyword";
        this.confirmpassword = await pbkdf2hw.hash(pw);
        this.role = await ROLE.USER;
    }
    next();
})

module.exports = mongoose.model('User', UserSchema);