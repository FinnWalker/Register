const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const mongoDB = "mongodb://localhost/register";
mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = global.Promise;

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.set("secretKey", "nodeRestApi");

app.use("/", express.static("public"));

const users = require("./routes/users");
app.use("/users", users);

function validateUser(req, res, next) {
  jwt.verify(req.headers["x-access-token"], req.app.get("secretKey"), function(
    err,
    decoded
  ) {
    if (err) {
      res.status(401).json({ message: "Invalid token" });
    } else {
      // add user id to request
      if (decoded.id) {
        req.body.userId = decoded.id;
        next();
      } else {
        res.status(300).json({ message: "This token is not valid" });
      }
    }
  });
}

app.use(function(err, req, res, next) {
  console.log(err);
  if (err.status === 404) {
    res.status(404).json({ message: "Not found" });
  } else {
    res.status(500).json({ message: "Something went wrong" });
  }
});

const server = app.listen(1111);
