const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
const db = new sqlite3.Database("./database.sqlite");

app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const SECRET_KEY = "seu_segredo";

// Criar tabelas do banco de dados
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        theme TEXT,
        score INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        theme TEXT,
        question TEXT,
        options TEXT,
        answer TEXT,
        explanation TEXT
    )`);

    // Inserir perguntas caso a tabela esteja vazia
    db.get("SELECT COUNT(*) AS count FROM questions", (err, row) => {
        if (row.count === 0) {
            const questions = [
                { theme: "Matemática", question: "Quanto é 2 + 2?", options: ["3", "4", "5", "6"], answer: "4", explanation: "2 + 2 = 4." },
                { theme: "Matemática", question: "Quanto é 5 x 5?", options: ["10", "20", "25", "30"], answer: "25", explanation: "5 vezes 5 é 25." },
                { theme: "História", question: "Quem foi o primeiro presidente do Brasil?", options: ["Juscelino Kubitschek", "Getúlio Vargas", "Deodoro da Fonseca", "Dom Pedro II"], answer: "Deodoro da Fonseca", explanation: "Ele assumiu em 1889." },
                // Adicione mais questões aqui...
            ];

            const stmt = db.prepare(`INSERT INTO questions (theme, question, options, answer, explanation) VALUES (?, ?, ?, ?, ?)`);
            questions.forEach(q => stmt.run(q.theme, q.question, JSON.stringify(q.options), q.answer, q.explanation));
            stmt.finalize();
        }
    });
});

// Registro de usuário
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (user) return res.status(400).json({ message: "Usuário já existe" });

        const hashedPassword = bcrypt.hashSync(password, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function () {
            res.json({ message: "Usuário cadastrado com sucesso" });
        });
    });
});

// Login
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: "Usuário ou senha inválidos" });
        }
        const token = jwt.sign({ userId: user.id }, SECRET_KEY);
        res.json({ token, username });
    });
});

// Buscar perguntas por tema
app.get("/questions/:theme", (req, res) => {
    const theme = req.params.theme;
    db.all("SELECT * FROM questions WHERE theme = ?", [theme], (err, rows) => {
        res.json(rows);
    });
});

// Salvar pontuação
app.post("/score", (req, res) => {
    const { token, theme, score } = req.body;
    const decoded = jwt.verify(token, SECRET_KEY);
    if (!decoded) return res.status(401).json({ message: "Não autorizado" });

    db.run("INSERT INTO scores (user_id, theme, score) VALUES (?, ?, ?)", [decoded.userId, theme, score], () => {
        res.json({ message: "Pontuação salva!" });
    });
});

app.listen(3000, () => console.log("Servidor rodando na porta 3000"));
