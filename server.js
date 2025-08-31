const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();
const crypto = require('crypto');
const zxcvbn = require("zxcvbn");

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();

const SECRET = process.env.SECRET;


// ----- Middleware -----
app.use(cors({
    origin: [
        "http://localhost:5173",
        "https://anime-app-94dd.vercel.app",
        /\.vercel\.app$/
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));
app.use(express.json());

// ----- Connect to MongoDB -----
mongoose.connect(
    process.env.MONGODB_URI,
    { useNewUrlParser: true, useUnifiedTopology: true }
)
    .then(() => console.log("✅ Connected to MongoDB"))
    .catch(err => console.error("❌ Connection error", err));

// ----- User Schema -----
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    favorites: { type: [mongoose.Schema.Types.Mixed], default: [] },
    customLists: {
        type: [
            {
                id: { type: String, required: true },
                name: { type: String, required: true },
                anime: { type: [mongoose.Schema.Types.Mixed], default: [] },
                createdAt: { type: Date, default: Date.now }
            }
        ],
        default: []
    }
});
const User = mongoose.model("User", userSchema);

// ----- Middleware to protect routes -----
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token" });
        req.user = user;
        next();
    });
}

// ----- Routes -----

// Get all users (password hidden)
app.get("/users", async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// Register user
const Joi = require('joi');

const registerSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string()
        .min(8)
        .max(128)
        .required()
        .pattern(new RegExp('^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]+$'))
});

app.post("/users", async (req, res) => {
    try {
        // Validate input using Joi
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { name, email, password } = value;

        // Password strength check
        const passwordStrength = zxcvbn(password);
        if (passwordStrength.score < 3) {
            return res.status(400).json({ error: "Password is too weak. Use a stronger one." });
        }

        // Check for existing user by email
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ error: "Email already in use" });

        // Check for existing username
        const existingName = await User.findOne({ name });
        if (existingName) return res.status(409).json({ error: "Username already in use" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString("hex");

        const user = new User({ name, email, password: hashedPassword, verificationToken });
        await user.save();

        const verificationLink = `https://anime-backend-fl5o.onrender.com/verify-email?token=${verificationToken}`;

        await sgMail.send({
            to: email,
            from: 'animeapp62@gmail.com',
            subject: "Verify your email address",
            text: `Please click the following link to verify your email: ${verificationLink}`,
            html: `<p>Please click the following link to verify your email:</p>
                   <a href="${verificationLink}">${verificationLink}</a>`
        });

        res.status(201).json({ message: "User registered. Please check your email to verify your account." });

    } catch (err) {
        console.error("Error registering user:", err);
        res.status(500).json({ error: "Server error. Please try again later." });
    }
});


// Login user
app.post("/users/login", async (req, res) => {
    try {
        const { name, password } = req.body;
        if (!name || !password) {
            return res.status(400).json({ error: "Name and password are required" });
        }

        const user = await User.findOne({ name });
        if (!user) return res.status(400).json({ error: "User not found" });

        // ✅ Check if the user is verified
        if (!user.isVerified) {
            return res.status(403).json({ error: "Please verify your email to log in" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(403).json({ error: "Invalid password" });
        }

        const token = jwt.sign({ id: user._id, name: user.name }, SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// Add/Remove Favorites
app.put("/users/favorites", authenticateToken, async (req, res) => {
    try {
        const { anime } = req.body; // full anime object
        if (!anime || !anime.mal_id) return res.status(400).json({ error: "Anime is required" });

        const user = await User.findById(req.user.id);

        const exists = user.favorites.some(fav => fav.mal_id === anime.mal_id);

        if (exists) {
            user.favorites = user.favorites.filter(fav => fav.mal_id !== anime.mal_id);
        } else {
            user.favorites.push(anime);
        }

        await user.save();
        res.json({ favorites: user.favorites });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// Fetch Favorites
app.get("/users/favorites", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json(user.favorites);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// Get user custom lists
app.get("/users/custom-lists", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json(user.customLists);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// Update user's custom lists
app.put("/users/custom-lists", authenticateToken, async (req, res) => {
    try {
        const { customLists } = req.body;
        if (!customLists) return res.status(400).json({ error: "customLists is required" });

        const user = await User.findById(req.user.id);
        user.customLists = customLists;
        await user.save();

        res.json(user.customLists);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// ✅ Email verification route
app.get("/verify-email", async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).send("Invalid verification link.");
        }

        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).send("Invalid or expired token.");
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();

        res.send("Email successfully verified! You can now log in.");
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/me", authenticateToken, (req, res) => {
    res.json({ id: req.user.id, name: req.user.name });
});

// ----- Start server -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});