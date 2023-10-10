const express = require('express')
const router = express.Router()
const { ensureAuth } = require('../middleware/authChecker')
const File = require('../models/Files')

// @desc    Show add page
// @route   GET /files/add
router.get('/add', ensureAuth, (req, res) => {
    res.render('files/add', {
        layout: './layouts/modify',
        title: 'Add',
    })
})

// @desc    Process add form
// @route   POST /files
router.post('/', ensureAuth, async (req, res) => {
    try {

        req.body.user = req.user.id

        if(await File.create(req.body)) {
            req.flash(
                'success_msg',
                'File Added Successfully'
            );
            res.redirect('/dashboard')
        } else {
            req.flash(
                'error_msg',
                'Failed to add the file'
            );
        }

    } catch (err) {
        console.error(err);
        res.render('error/500')
    }
})

// @desc    Show edit page
// @route   GET /stories/edit/:id
router.get('/edit/:id', ensureAuth, async (req, res) => {

    try {
        
        const file = await File.findOne({_id: req.params.id}).lean()
    
        if(!file) {
            return res.render('error/404')
        }
    
        if(file.user != req.user.id) {
            res.redirect('/dashboard')
        } else {
            res.render('files/edit', {
                layout: './layouts/modify',
                title: 'Edit',
                file,
            })
        }

    } catch (err) {

        console.error(err)
        return res.render('error/500')

    }
    
})

// @desc    Update File
// @route   PUT /files/:id
router.put('/:id', ensureAuth, async (req, res) => {

    try {
        
        let file = await File.findById(req.params.id).lean()

        if(!file) {
            return res.render('error/404')
        }

        if(file.user != req.user.id) {
            res.redirect('/dashboard')
        } else {
            file = await File.findOneAndUpdate({ _id: req.params.id }, req.body, {
            new: true,
            runValidators: true
        })
        req.flash(
            'success_msg',
            'File Edited Successfully'
        );

        res.redirect('/dashboard');
    }
    } catch (error) {
        console.error(err)
        return res.render('error/500')
    }
    
})

// @desc    Delete File
// @route   DELETE /files/:id
router.delete('/:id', ensureAuth, async (req, res) => {
    try {

        if(await File.deleteOne({ _id: req.params.id })) {
            req.flash(
                'success_msg',
                'File Deleted Successfully'
            );
            res.redirect('/dashboard')
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

module.exports = router