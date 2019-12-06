const userModel = require("../models/users");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sanitize = require("mongo-sanitize");
const nodemailer = require("nodemailer");

async function sendVerificationEmail(email, token) {
  console.log("trying");
  let transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: "hsbcsydney7@gmail.com", // generated ethereal user
      pass: "S95Qc6hWRBnY" // generated ethereal password
    }
  });

  let message = {
    from: "finn@catalystvr.com.au",

    to: email,

    subject: "Verify your account",

    html: `<a href="http://192.168.1.174:1111/users/verify?token=${token}">Verify your account</a>`
  };
  let info = await transporter.sendMail(message);

  console.log("Message sent: %s", info.messageId);
}

module.exports = {
  create: function(req, res, next) {
    const email = sanitize(req.body.email);
    const password = sanitize(req.body.password);

    if (email && password) {
      userModel.findOne({ email }, function(err, user) {
        if (err) {
          next(err);
        } else if (user) {
          res.json({ message: "Email taken" });
        } else {
          const token = jwt.sign({ email: email }, req.app.get("secretKey"), {
            expiresIn: "7d"
          });
          userModel.create(
            { email, password, active: false, verification_token: token },
            function(err, result) {
              if (err) {
                next(err);
              } else {
                sendVerificationEmail(email, token);
                res.json({ message: "Account created. Activate within 7 days" });
              }
            }
          );
        }
      });
    } else {
      res.status(400).json({ message: "Please include a name and password" });
    }
  },

  authenticate: function(req, res, next) {
    const email = sanitize(req.body.email);
    const password = sanitize(req.body.password);
    if (email && password) {
      userModel.findOne({ email }, function(err, userInfo) {
        if (err) {
          next(err);
        } else {
          if (userInfo) {
            if (userInfo.active == false) {
              res
                .status(200)
                .json({ message: "This account hasn't been activated" });
            } else if (
              userInfo &&
              bcrypt.compareSync(password, userInfo.password)
            ) {
              const token = jwt.sign(
                { id: userInfo._id },
                req.app.get("secretKey"),
                { expiresIn: "24h" }
              );
              res.json({ token });
            } else {
              res.status(401).json({ message: "Invalid credentials" });
            }
          } else {
            res.status(401).json({ message: "Invalid credentials" });
          }
        }
      });
    } else {
      res.status(400).json({ message: "Please include a name and password" });
    }
  },
  verifyEmail: function(req, res, next) {
    const token = sanitize(req.query.token);
    if (token) {
      jwt.verify(token, req.app.get("secretKey"), function(err, decoded) {
        if (err) {
          res
            .status(300)
            .json({ message: "This verification token is not valid" });
        } else if (decoded.email) {
          userModel.findOne({ email: decoded.email }, function(err, userInfo) {
            if (err) {
              next(err);
            } else {
              if (userInfo) {
                userInfo.active = true;
                userInfo.save().then(() => {
                  res.status(200).send("Email verified");
                });
              }
            }
          });
        } else {
          res
            .status(300)
            .json({ message: "This verification token is not valid" });
        }
      });
    } else {
      res.status(300).json({ message: "No verification token supplied" });
    }
  }
};
