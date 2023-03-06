global.express = require('express');
global.session = require('express-session');
global.bodyParser = require('body-parser');
global.bcrypt = require('bcryptjs');
global.http = require('http');
global.CryptoJS = require('crypto-js');
const SECRET_KEY = 'goifiyhfksvjkhvihf';
var rt = require('requestify');
global.app = express();

app.use(session({ secret: 'nirma@123', resave: true, saveUninitialized: true }));
app.use(express.json());
app.listen(9000);


app.post('/create_hash', (req, res) => {
    const sr = 10;
    password = req.body.password
    bcrypt.genSalt(sr, function(err, salt) {
        if (err) {
            res.send("Error");
        } else {
            bcrypt.hash(password, salt, function(err, hash) {
                if (err) {
                    res.send("Error");
                } else {
                    res.send(hash);
                }
            });
        }
    });
});

app.post('/get_link', (req,res)=>{
    const sr = 10;
    const pass = Math.floor((Math.random() * 999999) + 1);
    const password = pass.toString()
    bcrypt.genSalt(sr, function(err, salt) {
        if (err) {
            res.send("Error");
        } else {
            bcrypt.hash(password, salt, function(err, hash) {
                if (err) {
                    res.send("Error");
                } else {
                    var b64 = hash.toString();
                    var e64 = CryptoJS.enc.Base64.parse(b64);
                    var eHex = e64.toString(CryptoJS.enc.Hex);
                    res.send(eHex);
                }
            });
        }
    });
})

app.post("/check_password",(req,res)=>{
    bcrypt.compare(req.body.password, req.body.db, (err, r) => {

        if (r == true) {
            return res.send("ok");
        } else {
            return res.send("Not Ok");
        }
    });
});

const SECRET = 'goifiyhfksvjkhvihf';
function encryptionLink(plainText){
    var b64 = CryptoJS.AES.encrypt(plainText, SECRET).toString();
    var e64 = CryptoJS.enc.Base64.parse(b64);
    var eHex = e64.toString(CryptoJS.enc.Hex);
    return eHex;
}

function decryptedLink(cipherText){
    var reb64 = CryptoJS.enc.Hex.parse(cipherText);
    var bytes = reb64.toString(CryptoJS.enc.Base64);
    var decrypt = CryptoJS.AES.decrypt(bytes, SECRET);
    var plain = decrypt.toString(CryptoJS.enc.Utf8);
    return plain;
 }

app.post('/get_id_hash',(req,res)=>{
    const id = req.body.id;
    return res.send(encryptionLink(id));
})

app.post('/get_decrypted_hash',(req,res)=>{
    const id = req.body.id;
    return res.send(decryptedLink(id));
});