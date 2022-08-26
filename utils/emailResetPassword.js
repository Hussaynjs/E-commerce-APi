const sendEmail = require('./email')

const emailPasswordResetMessage = ({ name, email, token, origin }) => {
    const linkUri = `${origin}/user/reset-password?token=${token}&email=${email}`
    const message = `please click the link to reset password  <a href="${linkUri}">here</a>`

    return sendEmail({
        to: email,
        subject: 'Reset Password',
        html: `<h4>hello ${name}</h4>
        <p>${message}</p>
        `
    })
}


module.exports = emailPasswordResetMessage