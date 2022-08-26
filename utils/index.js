const { createJWT, isTokenValid, attachCookiesToResponse } = require('./jwt');
const createTokenUser = require('./createTokenUser');
const checkPermissions = require('./checkPermisions');
const emailVerificationMessage = require('./emailVerification')
const emailPasswordResetMessage = require('./emailResetPassword')


module.exports = {
    createJWT,
    isTokenValid,
    attachCookiesToResponse,
    createTokenUser,
    checkPermissions,
    emailVerificationMessage,
    emailPasswordResetMessage
};
