const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");
const { ObjectID } = require("mongodb");
const GitHubStrategy = require("passport-github").Strategy;
require("dotenv").config();

module.exports = (app, db, passport) => {
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser((id, done) => {
    db.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      done(null, doc);
    });
  });

  passport.use(
    new LocalStrategy(function (username, password, done) {
      db.findOne({ username: username }, function (err, user) {
        console.log("User " + username + " attempted to log in.");
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false);
        }
        if (!bcrypt.compareSync(password, user.password)) {
          return done(null, false);
        }
        return done(null, user);
      });
    })
  );

  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL:
          "https://Advanced-Node-and-Express.teknician.repl.co/auth/github/callback",
      },
      (accessToken, refreshToken, profile, cb) => {
        console.log(profile);
      }
    )
  );
};
