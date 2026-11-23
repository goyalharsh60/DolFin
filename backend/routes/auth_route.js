require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const prisma = require("../services/prisma_client");
const jwt = require("jsonwebtoken");

let router = express.Router();


// register route 
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate input
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password are required" });
  }

  // Check if the email already exists
  const existingEmail = await prisma.user.findUnique({
    where: { email },
  });
  if (existingEmail) {
    return res.status(409).json({ message: "Email already exists" });
  }

  // Hash the password and create a new user
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword,
      },
    });
    res.status(201).json({ message: "User registered successfully", userId: user.id });
    }

  catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }


}); 


// login route 
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  // Check if the user exists
  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // login successful, generate JWT token and send it in the response
    const token = jwt.sign(user, process.env.SECRET_KEY);

    res.status(200).json({ message: "Login successful", userId: user.id, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});



module.exports = router;
