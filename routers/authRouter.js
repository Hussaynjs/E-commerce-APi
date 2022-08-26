const express = require('express');
const router = express.Router();
const {
    authenticateUser
} = require('../middleware/auth');

const { register, login, logout, verifyEmail,
    forgotPassword,
    resetPassword } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.route('/verify-email', verifyEmail)
router.route('/forgot-Password', forgotPassword)
router.route('/reset-password', resetPassword)
router.get('/logout', authenticateUser, logout);

module.exports = router;
