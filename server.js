const express = require("express");
const { prisma } = require("./database/db");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const app = express();
const port = 3004;

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body || {};
  if (
    typeof username !== "string" ||
    !username.trim() ||
    typeof password !== "string" ||
    !password.trim()
  )
    return res.status(401).json({ error: "Invalid credentials" });
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const user = await prisma.user.create({
      data: {
        username: username.trim(),
        password: hash,
      },
    });
    res.json(user);
  } catch (err) {
    console.log(err);
    return res.status(500).send();
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (
    typeof username !== "string" ||
    !username.trim() ||
    typeof password !== "string" ||
    !password.trim()
  )
    return res.status(401).json({ error: "Invalid credentials" });
  try {
    const user = await prisma.user.findUnique({
      where: { username: username.trim() },
    });
    if (!user) return res.json({ message: "No user found" });
    const result = await bcrypt.compare(password, user.password);
    if (!result) return res.json({ message: "Invalid credentials" });
    res.send(`Welcome ${user.username}`);
  } catch (err) {
    console.log(err);
    return res.status(500).send();
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
