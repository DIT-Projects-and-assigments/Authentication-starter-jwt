const mysql = require('mysql')
const router = require('express').Router();   
const db = require('../config/database')
const passport = require('passport');
const utils = require('../lib/utils');

router.get('/protected', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    res.status(200).json({ success: true, msg: "You are successfully authenticated to this route!"});
});

// Validate an existing user and issue a JWT
router.post('/login', function(req, res, next){

    let name = req.body.username
    db.getUserByUsername(name)

        .then((user) => {

            if (!user) {
                return res.status(401).json({ success: false, msg: "could not find user" });
            }
            
            // Function defined at bottom of app.js
            const isValid = utils.validPassword(req.body.password, user.hash, user.salt);
            
            if (isValid) {

                const tokenObject = utils.issueJWT(user);

                res.status(200).json({ success: true, user: user, token: tokenObject.token, expiresIn: tokenObject.expires });

            } else {

                res.status(401).json({ success: false, msg: "you entered the wrong password" });

            }

        })
        .catch((err) => {
            next(err);
        });


});

router.post('/register', (req, res, next) => {

    const saltHash = utils.genPassword(req.body.password)

    const salt = saltHash.salt;
    const hash = saltHash.hash;

    //if is admin 
    if(req.body.isAdmin)
    {
        db.insertAdmin(req.body.username, hash, salt)
        
        .then((result) =>
        {
            console.log("Admin Inserted successfuly")
            res.status(200).json({success: true, msg:"The admin is aded successfuly to the App"})
        })
        .catch((err) =>
        {
            res.send(`The error ocured!. ${err.message}. Makesure you correct the error and try again.`)
            console.log("There was an error occured during insertation... \n " + err)
        })
    }
    else
    {
        db.insertUser(req.body.username, hash,salt)

        .then((result) =>
        {
            console.log(result)
            
            let insertedUser = {
                username: req.body.username,
                hash: hash,
                salt: salt
            }

            console.log(insertedUser);

            const JWT = utils.issueJWT(insertedUser)
            
            res.json({success: true, user: insertedUser, token:JWT.token , issued: JWT.iat, expiresIn:JWT.expires})

        })
        .catch((err) =>
        {
            console.log(err)
            next(err)
           // res.send(`Ooooooops! encoutered the error ${err.message}. User with the same username already exist. `);
        })
    }

    
});
router.get('/protected', passport.authenticate('jwt', {session: false}), (req,res,next) =>
{
    res.status(200).json({success: true, msg: "You are authorized!!"})
})

module.exports = router;

