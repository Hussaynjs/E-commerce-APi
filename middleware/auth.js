const CustomError = require('../errors');
const { isTokenValid, attachCookiesToResponse } = require('../utils');
const Token = require('../models/Token')
const authenticateUser = async (req, res, next) => {
    const { accessTokenJWT, refreshTokenJWT } = req.signedCookies;


    try {
        if (accessTokenJWT) {
            const payload = isTokenValid(accessTokenJWT)
            req.user = payload.user
            return next()
        }

        const payload = isTokenValid(refreshTokenJWT)
        const existingToken = await Token.findOne({ user: payload.user.userId, refreshToken: payload.refreshToken })

        if (!existingToken) {

            throw new CustomError.UnauthenticatedError('Authentication Invalid');
        }
        attachCookiesToResponse({
            res,
            user: payload.user,
            refreshToken: payload.refreshToken
        })

        req.user = payload.user;
        next()

    } catch (error) {

        throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }


};

const authorizePermissions = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            throw new CustomError.UnauthorizedError(
                'Unauthorized to access this route'
            );
        }
        next();
    };
};

module.exports = {
    authenticateUser,
    authorizePermissions,
};
