const bcryptjs = require("bcryptjs");
const router = require("express").Router();
const saltRounds = 10;
const User = require("../models/User.model");
const { isLoggedIn, isLoggedOut } = require("../middelwares/route-guard");

// const router = new Router();
// const { Router } = require("express");

router.get("/login", isLoggedOut, (req, res) => res.render("auth/login"));
router.get("/signup", (req, res) => res.render("auth/signup"));
router.get("/profile", isLoggedIn, (req, res) => {
  const user = req.session.currentUser;
  res.render("users/user-profile", { username: user.username });
});
router.get("/main", isLoggedIn, (req, res) => res.render("auth/main"));
router.get("/private", isLoggedIn, (req, res) => res.render("auth/private"));

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
  try {
    if (req.body.email && req.body.password) {
      const foundUser = await User.findOne({ email: req.body.email });
      if (!foundUser) {
        res.render("auth/signup", { errorMessage: "User not found" });
      } else if (bcryptjs.compareSync(req.body.password, foundUser.password)) {
        req.session.currentUser = foundUser;
        res.render("users/user-profile", { username: foundUser.username });
      } else {
        res.render("auth/login", { errorMessage: "Incorrect password." });
      }
    } else {
      res.render("auth/login", {
        errorMessage: "Incorrect email or password.",
      });
    }
  } catch (error) {
    next(error);
  }
});

router.post("/logout", async (req, res, next) => {
  req.session.destroy((error) => {
    if (error) next(error);

    res.redirect("/");
  });
});

module.exports = router;
