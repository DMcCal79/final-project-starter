const express = require('express');
const router = express.Router();
const jwt = require('jwt-simple');
const User = require('../models/UserModel');
const bcrypt = require('bcrypt-nodejs');
const passport = require('passport');

// Require our custom strategies
require('../services/passport');

const signinStrategy = passport.authenticate('signinStrategy', { session: false });

//Helper method that is used to create a token for a user
function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ userId: user.id, iat: timestamp }, process.env.SECRET)
}

router.post('/signin', signinStrategy, function(req, res, next) {
  res.json({ token: tokenForUser(req.user)});
});

router.post('/signup', function (req, res, next) {
  //Takes username & password from request body
  const { username, password } = req.body;

  //If no username or password was entered then return an error
  if (!username || !password) {
    return res.status(422)
      res.json({ error: 'You must provide an username and password' });
  }

  //Check for a user with the current user name
  User.findOne({ username }).exec()
    .then((existingUser) => {
      //If the user does exist already then return an error on sign up
      if (existingUser) {
        return res.status(422).json({ error: 'Username is in use'});
      }

      //If the user does not already exist then create the user
      //Use bycrypt to hash their password
      bcrypt.genSalt(10, function(salt) {
        bcrypt.hash(password, salt, null, function(err, hashedPassword) {
          if (err) {
            return next(err);
          }

          //Create new user with the supplied username and hashed password
          const user = new User ({ username, password: hashedPassword});

          //Save and return the user
          user.save()
            .then(user => res.json({ token: tokenForUser(user) }));
        });
      })
      .catch(err => next(err));
    });
});

const authStrategy = passport.authenticate('authStrategy', { session: false });

router.get('/secret', authStrategy, function(req, res, next) {
  res.send(`The current user is ${req.user.username}`);
});

module.exports = router;
