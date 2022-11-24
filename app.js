require("dotenv").config();
const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require("./database-connect.js")();
const { body, validationResult } = require("express-validator");

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne(
      {
        username: username,
      },
      (err, user) => {
        if (err) return done(err);
        if (!user) {
          console.error(`Invalid username: ${username} not found!`);
          return done(null, false, {
            message: "Incorrect username or password",
          });
        }

        bcrypt.compare(password, user.password, (err, res) => {
          if (res) {
            console.log(`${user} supplied correct password '${password}'`);
            return done(null, user);
          }

          console.error(`Invalid password: '${user.password}'`);
          return done(null, false, { message: "Incorrect password" });
        });
      }
    );
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

app.use(
  session({
    secret: "cats",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.render("index", {
    user: req.user,
  });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post(
  "/sign-up",
  [
    body("username")
      .isAlpha()
      .withMessage("Please specify a valid username")
      .trim()
      .isLength({ min: 4, max: 16 })
      .withMessage("Username must be between 4 and 16 characters")
      .escape(),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long")
      .escape(),
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.redirect("/sign-up");
      console.log("Error signing up: ");
      console.log(errors.array());
      return;
    }

    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
      if (err) return next(err);
      const user = new User({
        username: req.body.username,
        password: hashedPassword,
        // password: req.body.password,
      }).save((err) => {
        if (err) return next(err);
        res.redirect("/");
      });
    }); // end bcrypt
  }
);

// LOGIN route
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

// LOGOUT route
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
