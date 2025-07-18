const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const dotenv = require("dotenv").config()



const app = express();
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
  "http://127.0.0.1:5500",              // VS Code Live Server
  "http://localhost:5500",              // Alternative
  "http://192.168.197.231:5500",        // Your actual IP for phone access
  "https://sweetlifemw.github.io",   // Replace with your GitHub Pages URL
  "https://sweetlife-1dpx.onrender.com" // Your backend URL (for Render)
];

// CORS middleware
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log("Blocked by CORS:", origin);
      callback(new Error("CORS not allowed for this origin"));
    }
  },
  credentials: true
}));





//  Load environment variables (Render reads from dashboard)
const MONGODB_URI =process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

console.log(process.env.MONGODB_URI);

//  Connect to MongoDB
mongoose.connect( MONGODB_URI)
  .then(() => console.log(" MongoDB connected"))
  .catch(err => {
    console.error(" MongoDB connection error:");
    console.error(err);
  });



// Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  username: String,
  phone: { type: String, unique: true },
  gender: String,
  district: String,
  password: String,
  accountNumber: String,
  balance: { type: String, default: "00.00" }
});

const User = mongoose.model("User", userSchema);

// Generate account number
function generateAccountNumber() {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

// Normalize phone number
function normalizePhone(phone) {
  if (!phone) return "";
  phone = phone.trim();
  if (phone.startsWith("+265")) return phone.slice(4);
  if (phone.startsWith("265")) return phone.slice(3);
  if (phone.startsWith("088")) return phone;
  if (phone.startsWith("88")) return "0" + phone;
  return phone;
}

// Middleware to check token
function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(403).json({ message: "Invalid token" });
  }
}

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { firstName, lastName, username, phone, gender, district, password, confirmPassword } = req.body;

    if (!firstName || !lastName || !username || !phone || !gender || !district || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (password !== confirmPassword) return res.status(400).json({ message: "Passwords do not match" });

    const normalizedPhone = normalizePhone(phone);
    const existingUser = await User.findOne({ phone: normalizedPhone });
    if (existingUser) return res.status(400).json({ message: "Phone number already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const accountNumber = generateAccountNumber();

    const newUser = new User({
      firstName,
      lastName,
      username: username.toLowerCase(),
      phone: normalizedPhone,
      gender,
      district,
      password: hashedPassword,
      accountNumber
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: "7d" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,               // required for cross-origin cookie in production
      sameSite: "None",           // required for cross-origin cookie
      maxAge: 7 * 24 * 60 * 60 * 1000
      });

    res.status(201).json({
      message: "Account created successfully",
      username: newUser.username,
      accountNumber: newUser.accountNumber,
      district: newUser.district,
      balance: newUser.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});
// Keep-alive ping route for uptime monitoring
app.get("/api/ping", (req, res) => {
  res.status(200).send("pong");
});


// Login
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ message: "Phone/username and password required" });

    const normalizedPhone = normalizePhone(phone);
    const lowerUsername = phone.toLowerCase();

    const user = await User.findOne({
      $or: [{ phone: normalizedPhone }, { username: lowerUsername }]
    });

    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,               // required for cross-origin cookie in production
      sameSite: "None",           // required for cross-origin cookie
      maxAge: 7 * 24 * 60 * 60 * 1000
});

    res.json({
      message: "Logged in successfully",
      username: user.username,
      accountNumber: user.accountNumber,
      district: user.district,
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Get current user
app.get("/api/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ loggedIn: true, user });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully" });
});



// Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
