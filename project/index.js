const express = require("express");
const port = 8000;
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const nodemailer = require("nodemailer");


const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "shayanisdevil@gmail.com",     
    pass: "enlljlnqxwqwlepu",       
  },
});
const app = express();
app.use(express.json());
const JWT_SECRET = "mySecretKey";
mongoose.connect("mongodb://127.0.0.1:27017/project")
  .then(() => console.log("Mongoose connected"))
  .catch((err) => console.log("MONGO error", err));

const schema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
});
const user = mongoose.model("user", schema);

app.post("/signup", async (req, res) => {
  try {
    console.log("Incoming request:", req.body); 

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      console.log("Validation failed");
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await user.findOne({ email });
    if (existingUser) {
      console.log("User already exists");
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await user.create({
      name,
      email,
      password: hashedPassword,
      isVerified: false,
    });

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, {
      expiresIn: "1d",
    });
    const confirmURL = `http://localhost:8000/confirm/${token}`;
    await transporter.sendMail({
        from: '"Project Support" <shayan>', 
      to: "shayanisdevil@gmail.com",
      subject: "Please confirm your email",
      html: `<h1>Welcome, ${name}!</h1>
             <p>Please confirm your email by clicking the link below:</p>
             <a href="${confirmURL}">Confirm Email</a>`,
    });

    res.status(201).json({
      message:
        "User created successfully. Please check your email for confirmation link.",
    });
  } catch (error) {
    console.error("Error in /signup:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});
app.get("/confirm/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, JWT_SECRET);
    await user.findByIdAndUpdate(decoded.userId, { isVerified: true });
    res.status(200).send("<h1>Email Verified Successfully! </h1>");
  } catch (error) {
    console.error("Error in /confirm:", error);
    res.status(400).send("<h1>Invalid or Expired Token</h1>");
  }
});
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }
    const foundUser = await user.findOne({ email });
    if (!foundUser) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    if (!foundUser.isVerified) {
      return res.status(401).json({ message: "Please verify your email first" });
    }
    const isMatch = await bcrypt.compare(password, foundUser.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const accessToken = jwt.sign({ userId: foundUser._id }, JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId: foundUser._id }, JWT_SECRET, { expiresIn: "7d" });

    res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Error in /login:", error);
    res.status(500).json({ message: "Server error" });
  }
});
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(404).json({ message: "User not found" });
    }
    const resetToken = jwt.sign({ userId: existingUser._id }, JWT_SECRET, {
      expiresIn: "10m",
    });
    const resetURL = `http://localhost:8000/reset-password/${resetToken}`;

    await transporter.sendMail({
      from: '"Project Support" <shayan>', 
      to: "shayanisdevil@gmail.com",
      subject: "Password Reset Request",
      html: `<h1>Reset Your Password</h1>
             <p>Click below to reset your password (valid for 10 minutes):</p>
             <a href="${resetURL}">Reset Password</a>`,
    });

    res.status(200).json({
      message: "Password reset email sent! Please check your inbox.",
    });
  } catch (error) {
    console.error("Error in /forgot-password:", error);
    res.status(500).json({ message: "Server error" });
  }
});
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({ message: "New password is required" });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await user.findByIdAndUpdate(
      decoded.userId,
      { password: hashedPassword },
      { new: true }
    );
    await transporter.sendMail({
      from: `"Project Support" <${transporter.options.auth.user}>`,
      to: "shayanisdevil@gmail.com",
      subject: "Your Password Was Reset Successfully",
      html: `
        <h1>Hello ${updatedUser.name},</h1>
        <p>Your password has been successfully reset.</p>
        <br/>
        <p>Thank you</p>
      `,
    });
    res.status(200).json({ message: "Password reset successful!" });
  } catch (error) {
    console.error("Error in /reset-password:", error);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});
app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});

