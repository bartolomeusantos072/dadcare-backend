import express from "express";
import Tarefa from "../models/Tarefa.js";
import { autenticar } from "../middleware/auth.js";

const router = express.Router();

// Criar nova tarefa (somente logado)
router.post("/", autenticar, async (req, res) => {
  try {
    const nova = await Tarefa.create({
      titulo: req.body.titulo,
      descricao: req.body.descricao,
      usuarioId: req.usuario.id, // vem do token
    });
    res.json(nova);
  } catch (err) {
    res.status(500).json({ msg: "Erro ao criar tarefa", erro: err.message });
  }
});

// Listar tarefas do usuário logado
router.get("/", autenticar, async (req, res) => {
  try {
    const tarefas = await Tarefa.find({ usuarioId: req.usuario.id });
    res.json(tarefas);
  } catch (err) {
    res.status(500).json({ msg: "Erro ao listar tarefas", erro: err.message });
  }
});

export default router;
