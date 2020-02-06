const { Router } = require("express");
const config = require("../config/default.json");
const User = require("../models/User");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = Router();

//api/auth/register
router.post(
  "/register",
  [
    check("email", "Wrong email").isEmail(),
    check("password", "Minimum length 6").isLength({ min: 6 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Wrong registrarion data"
        });
      }
      const { email, password } = req.body;
      const candidate = await User.findOne({ email: email });
      if (candidate) {
        return res.status(400).json({
          message: "Error = User already exists"
        });
      }
      const hashedPassword = await bcrypt.hash(password, 8);
      const user = new User({ email: email, password: hashedPassword });
      await user.save();
      res.status(201).json({
        message: "User was created"
      });
    } catch (error) {
      res.status(500).json({
        message: "Smth wrong"
      });
    }
  }
);
//api/auth/login
router.post(
  "/login",
  [
    check("email", "Please enter correct email")
      .normalizeEmail()
      .isEmail(),
    check("password", "Please enter password").exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Wrong login data"
        });
      }
      const { email, password } = req.body;
      const user = await User.findOne({ email: email });
      if (!user) {
        return res.status(400).json({ message: "User not found" });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Wrong password" });
      }
      const token = jwt.sign({ userId: user.id }, config.get("jwtSecret"), {
        expiresIn: "1h"
      });
      res.json({
        token: token,
        userId
      });
    } catch (error) {
      res.status(500).json({
        message: "Smth wrong"
      });
    }
  }
);

module.exports = router;
