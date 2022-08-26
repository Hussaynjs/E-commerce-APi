const User = require('../models/User');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const crypto = require('crypto')
const { attachCookiesToResponse, createTokenUser, emailVerificationMessage, emailPasswordResetMessage } = require('../utils');

const register = async (req, res) => {
    const { email, name, password } = req.body;

    const emailAlreadyExists = await User.findOne({ email });
    if (emailAlreadyExists) {
        throw new CustomError.BadRequestError('Email already exists');
    }

    // first registered user is an admin
    const isFirstAccount = (await User.countDocuments({})) === 0;
    const role = isFirstAccount ? 'admin' : 'user';

    const verificationToken = crypto.randomBytes(40).toString('hex')
    const user = await User.create({ name, email, password, role, verificationToken });

    // frontend uri

    const origin = 'https//localhost:3000'

    await emailVerificationMessage({
        name: user.name,
        email: user.email,
        verificationToken: user.verificationToken,
        origin
    })

    res.status(StatusCodes.CREATED).json({ msg: 'success! check your email to verify account' })
};

const verifyEmail = async (req, res) => {

    const { email, verificationToken } = req.body;

    if (!email || !verificationToken) {
        throw new CustomError.UnauthenticatedError('invalid verification')
    }

    const user = await User.findOne({ email })

    if (user.verificationToken !== verificationToken) {
        throw new CustomError.UnauthenticatedError('invalid verification')
    }

    user.verificationToken = ''
    user.isVerified = true;
    user.verified = Date.now()

    await user.save()

    res.status(StatusCodes.OK).json({ msg: 'success!' })
}



const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        throw new CustomError.BadRequestError('Please provide email and password');
    }
    const user = await User.findOne({ email });

    if (!user) {
        throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
        throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }

    if (!user.isVerified) {
        throw new CustomError.UnauthenticatedError('Invalid Credentials');

    }
    const tokenUser = createTokenUser(user);

    let refreshToken = ''
    const userToken = await Token.findOne({ user: user_id })

    if (userToken) {
        const { isValid } = userToken

        if (!isValid) {
            throw new CustomError.UnauthenticatedError('cannot login')
        }

        refreshToken = userToken.refreshToken;
        attachCookiesToResponse({ res, user: tokenUser, refreshToken });

        res.status(StatusCodes.OK).json({ user: tokenUser });
        return;

    }

    const userAgent = req.headers['user-agent']
    const ip = req.ip;
    refreshToken = crypto.randomBytes(40).toString('hex')

    await Token.create({ refreshToken, userAgent, ip, user: user_id })
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });

    res.status(StatusCodes.OK).json({ user: tokenUser });
};


const forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        throw new CustomError.BadRequestError('please provide email')
    }

    const user = await User.findOne({ email })

    if (user) {
        const passwordToken = crypto.randomBytes(70).toString('hex')
        // frontend uri

        const origin = 'https//localhost:3000'
        await emailPasswordResetMessage({
            name: user.name,
            email: user.email,
            token: passwordToken,
            origin
        })
    }

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = passwordToken;
    user.passwordTokenExpirationDate = passwordTokenExpirationDate

    await user.save()

    res.status(StatusCodes.OK).json({ msg: 'check your email to reset password' })
}

const resetPassword = async (req, res) => {
    const { passwordToken, email, newPassword, confirmPassword } = req.body;

    if (!oldPassword || !newPassword || !confirmPassword) {
        throw new CustomError.BadRequestError('please provide all valus')
    }
    if (newPassword !== confirmPassword) {
        throw new CustomError.BadRequestError('incorrect password')

    }
    const user = await User.findOne({ email })

    if (user) {
        const currentDate = new Date(Date.now)
        if (user.passwordToken === passwordToken && user.passwordTokenExpirationDate > currentDate) {
            user.password = newPassword;
            user.passwordToken = null
            user.passwordTokenExpirationDate = null
            await user.save()
        }

    }
    res.send('password changed')
}


const logout = async (req, res) => {

    await Token.findOneAndDelete({ user: req.user.userId })

    res.cookie('accessTokenJWT', '', {
        httpOnly: true,
        expires: new Date(Date.now()),
    });

    res.cookie('refreshTokenJWT', '', {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

module.exports = {
    register,
    login,
    logout,
    verifyEmail,
    forgotPassword,
    resetPassword
};
