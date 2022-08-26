const sendEmail = require('./email')

const emailVerificationMessage = ({ name, email, verificationToken, origin }) => {
    const linkUri = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`
    const message = `please click the link to verify email <a href="${linkUri}">here</a>`

    return sendEmail({
        to: email,
        subject: 'Verification Email',
        html: `<h4>hello ${name}</h4>
        <p>${message}</p>
        `
    })
}


module.exports = emailVerificationMessage