global.express = require('express');
global.session = require('express-session');
global.bodyParser = require('body-parser');
global.bcrypt = require('bcryptjs');
global.http = require('http');
var rt = require('requestify');
global.app = express();

app.use(session({ secret: 'nirma@123', resave: true, saveUninitialized: true }));
app.use(express.json());
app.listen(9001);

global.nodemailer = require('nodemailer');

global.transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '',
        pass: ''
    }
});

app.post('/send_link', (req, res) => {
    var email = req.body.email;
    console.log(req.body)
    var mailOptions = {
        from: 'ibatj7@gmail.com',
        to: email,
        subject: 'Verification Link',
        text: 'Verify Yourself on the following link \n' + req.body.link
    };
    transporter.sendMail(mailOptions, function(error, info) {
        if (error) {
            console.log(error);
            return res.send("Error");
        } else {
            console.log('Email sent: ' + info.response);
            return res.send("Ok");
        }
    });
});
