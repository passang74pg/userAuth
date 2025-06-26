const express = require('express');
const authController = require('../controllers/authController');
const router = express.Router();

// Root route for authentication
router.get('/', (req, res) => {
    res.render('pages/landing');
});

// Signup routes 
router.get('/signup', authController.getSignUp);
router.post('/signup', authController.postSignUp);
// Email verification route
router.get('/verify-email', authController.verifyEmail);

// login routes 
router.get('/login', authController.getLogin);
router.post('/login', authController.postLogin);

// forgot password routes
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);
router.get('/reset-password', authController.getResetPassword);
router.post('/reset-password', authController.resetPassword);

// Logout route
router.get('/logout', authController.logoutUser);

module.exports = router;