const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key";

app.use(express.json());
app.use("/uploads", express.static("uploads"));

// Initialize SQLite Database
const db = new sqlite3.Database("./crud.db", (err) => {
  if (err) console.error(err.message);
  console.log("Connected to SQLite database.");
});

// Create Users Table
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS blogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    title TEXT,
    description TEXT,
    image TEXT,
    FOREIGN KEY(userid) REFERENCES users(id)
)`);

// Multer Setup for Image Uploads
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    (err) => {
      if (err) return res.status(400).json({ error: "User already exists" });
      res.json({ message: "User registered successfully" });
    }
  );
});

// Login API
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user)
        return res.status(400).json({ error: "Invalid username or password" });

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid)
        return res.status(400).json({ error: "Invalid username or password" });

      const token = jwt.sign(
        { id: user.id, username: user.username },
        SECRET_KEY,
        {
          expiresIn: "1h",
        }
      );

      res.json({ token });
    }
  );
});

// Protected Route
app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: "Welcome to your profile!", user: req.user });
});

// Middleware to Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.header("Authorization");
  if (!authHeader) return res.status(401).json({ error: "Access denied" });

  const token = authHeader.split(" ")[1]; // Extract only the token

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// Create Blog API
app.post("/blog", authenticateToken, upload.single("image"), (req, res) => {
  const { title, description } = req.body;
  const image = req.file ? req.file.filename : null;
  const userid = req.user.id;

  db.run(
    "INSERT INTO blogs (userid, title, description, image) VALUES (?, ?, ?, ?)",
    [userid, title, description, image],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Blog created successfully", blogId: this.lastID });
    }
  );
});

// Get Blogs API
app.get("/blogs", (req, res) => {
  db.all("SELECT * FROM blogs", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Update Blog (Only by Owner)
app.put("/blog/:id", authenticateToken, upload.single("image"), (req, res) => {
  const { title, description } = req.body;
  const blogId = req.params.id;
  const userId = req.user.id;
  const image = req.file ? req.file.filename : null;

  db.get("SELECT * FROM blogs WHERE id = ?", [blogId], (err, blog) => {
    if (!blog) return res.status(404).json({ error: "Blog not found" });
    if (blog.userid !== userId)
      return res.status(403).json({ error: "Unauthorized" });

    let updateQuery =
      "UPDATE blogs SET title = ?, description = ? WHERE id = ?";
    let params = [title, description, blogId];

    if (image) {
      updateQuery =
        "UPDATE blogs SET title = ?, description = ?, image = ? WHERE id = ?";
      params = [title, description, image, blogId];
    }

    db.run(updateQuery, params, function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Blog updated successfully", updatedImage: image });
    });
  });
});

// Delete Blog (Only by Owner)
app.delete("/blog/:id", authenticateToken, (req, res) => {
  const blogId = req.params.id;
  const userId = req.user.id;

  db.get("SELECT * FROM blogs WHERE id = ?", [blogId], (err, blog) => {
    if (!blog) return res.status(404).json({ error: "Blog not found" });
    if (blog.userid !== userId)
      return res.status(403).json({ error: "Unauthorized" });

    db.run("DELETE FROM blogs WHERE id = ?", [blogId], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Blog deleted successfully" });
    });
  });
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
