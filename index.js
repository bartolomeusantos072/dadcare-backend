import helmet from "helmet";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import "./db.js";
import usuariosRouter from "./routes/usuarios.js";

dotenv.config();
const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API DadCare rodando 🚑");
});

app.use("/usuarios", usuariosRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
