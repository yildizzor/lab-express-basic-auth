const bcryptjs = require("bcryptjs");
const router = require("express").Router();
const saltRounds = 10;
const User = require("../models/User.model");

// const router = new Router();
// const { Router } = require("express");

router.get("/login", (req, res) => res.render("auth/login"));
router.get("/signup", (req, res) => res.render("auth/signup"));
router.get("/profile", (req, res) => res.render("users/user-profile"));

router.post("/signup", async (req, res, next) => {
 
  try {
    let response = await User.findOne({ username: req.body.username });
    if (!response) {
      const salt = bcryptjs.genSaltSync(10);
      const hashedPassword = bcryptjs.hashSync(req.body.password, salt);
      const newUser = await User.create({
        ...req.body,
        password: hashedPassword,
      });
      res.redirect("/profile");
    } else {
      res.render("auth/signup", { errorMessage: "Username already taken" });
    }
  } catch (err) {
    next(err);
  }
});

router.post("/login", async (req, res, next) => {
  const foundUser = await User.findOne({ email: req.body.email });

  if (foundUser) {
    let doesPasswordsMatch = bcryptjs.compareSync(
      req.body.password,
      foundUser.password
    );

    if (doesPasswordsMatch) {
      res.render("auth/profile", { username: foundUser });
    } else {
      res.render("auth/login", { errorMessage: "Password Incorrect" });
    }
  } else {
    res.render("auth/login", { errorMessage: "Incorrect Credentials" });
  }
});

module.exports = router;