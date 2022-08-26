const nodeMailer = require('nodemailer')
const nodemailerConfig = require('./nodemailerConfig')

const sendEmail = async ({ to, subject, html }) => {
    const test = await nodeMailer.createTestAccount()
    const transporter = await nodeMailer.createTransport(nodemailerConfig)

    return transporter.sendMail({
        from: '"hussaini musa" <hussainimusa566@gmail.com>',
        to,
        subject,
        html
    })
}

module.exports = sendEmail