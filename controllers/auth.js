const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const sgMail = require("@sendgrid/mail");
const { validationResult } = require("express-validator");
require("dotenv").config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const handleError = (err) => {
  const error = new Error(err);
  error.httpStatusCode = 500;
  return next(error);
};

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
    oldPage: {
      email: '',
      password: ''
    },
    validatorErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const error = validationResult(req);
  if (!error.isEmpty()) {
    console.log(error.array());
    return res.status(422).render("auth/login", {
      path: "/login",
      pageTitle: "Login",
      errorMessage: error.array()[0].msg,
      oldPage: {
        email: email,
        password: password,
      },
      validatorErrors: error.array(),
    });
  }

  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.status(422).render("auth/login", {
          path: "/login",
          pageTitle: "Login",
          errorMessage: "Invalid email or password",
          oldPage: {
            email: email,
            password: password,
          },
          validatorErrors: []
        });
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          return res.status(422).render("auth/login", {
            path: "/login",
            pageTitle: "Login",
            errorMessage: error ? error.array()[0].msg : null,
            oldPage: {
              email: email,
              password: password,
            },
            validatorErrors: error.array(),
          })
        })
        .catch((err) => {
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => handleError(err));
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
    oldPage: {
      email: "",
      password: "",
      confirmPassword: "",
    },
    validatorErrors: [],
  });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const error = validationResult(req);
  if (!error.isEmpty()) {
    console.log(error.array());
    return res.status(422).render("auth/signup", {
      path: "/signup",
      pageTitle: "Signup",
      errorMessage: error.array()[0].msg,
      oldPage: {
        email: email,
        password: password,
        confirmPassword: req.body.password,
      },
      validatorErrors: error.array(),
    });
  }

  bcrypt
    .hash(password, 12)
    .then((hashedPassword) => {
      const user = new User({
        email: email.toLowerCase(),
        password: hashedPassword,
        cart: { items: [] },
      });
      return user.save();
    })
    .then((result) => {
      res.redirect("/login");

      const msg = {
        to: email.toLowerCase().toString(),
        from: "160403501@live.unilag.edu.ng",
        subject: "Signup succeeded",
        text: "Welcome once again",
        html: "<h1>Welcome, shop whatever you like, anywhere at anytime.</h1>",
      };
      return sgMail
        .send(msg)
        .then(() => {
          console.log("Email sent");
        })
        .catch((err) => handleError(err));
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash("error", "No account with the email found");
          return res.redirect("/reset");
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then((result) => {
        res.redirect("/");
        const msg = {
          to: req.body.email,
          from: "160403501@live.unilag.edu.ng",
          subject: "Password reset",
          html: `
              <p>You requested apassword reset</p>
              <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password</p>
              `,
        };
        return sgMail
          .send(msg)
          .then(() => {
            console.log("Email sent");
          })
          .catch((err) => console.log(err[0]));
      })
      .catch((err) => handleError(err));
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then((user) => {
      let message = req.flash("error");
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token,
      });
    })
    .catch((err) => handleError(err));
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId,
  })
    .then((user) => {
      resetUser = user;
      return bcrypt.hash(newPassword, 12);
    })
    .then((hashedPassword) => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then((result) => {
      res.redirect("/");
    })
    .catch((err) => handleError(err));
};
