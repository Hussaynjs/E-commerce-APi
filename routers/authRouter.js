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
router.get('/verify-email', verifyEmail)
router.post('/forgot-Password', forgotPassword)
router.post('/reset-password', resetPassword)
router.delete('/logout', authenticateUser, logout);

module.exports = router;
