const express = require("express");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: 5432, // Default PostgreSQL port
  ssl: {
    rejectUnauthorized: false,
  },
});

const salt = bcrypt.genSaltSync(10);

app.use(express.json());

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const query = `INSERT INTO "users" (name, password, email) VALUES ($1, $2, $3);`;
    const values = [username, bcrypt.hashSync(password, salt), email];
    await pool.query(query, values);
    res.status(200).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "An error occurred during registration." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const query = `SELECT password FROM "users" WHERE name = $1;`;
    const values = [username];
    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      res.status(401).json({ message: "Invalid name or password." });
      return;
    }

    const hashedPassword = result.rows[0].password;
    const match = await bcrypt.compare(password, hashedPassword);

    if (match) {
      res.status(200).json({ message: "Login successful." });
    } else {
      res.status(401).json({ message: "Invalid username or password." });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "An error occurred during login." });
  }
});
