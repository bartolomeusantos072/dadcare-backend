
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import express from "express";
import Usuario from "../models/Usuario.js";
import { autenticarToken, gerarToken } from "../middleware/auth.js";

const router = express.Router();

// Cadastrar novo usuário
router.post("/signup", async (req, res) => {
  try {
    const { nome, email, senha, categoria } = req.body;

    const existe = await Usuario.findOne({ email });
    if (existe) return res.status(400).json({ msg: "E-mail já cadastrado" });

    const senhaHash = await bcrypt.hash(senha, 10);

    const novo = await Usuario.create({ nome, email, senha: senhaHash, categoria });
    res.json({ usuario: novo });
  } catch (err) {
    res.status(500).json({ msg: "Erro ao cadastrar usuário", erro: err.message });
  }
});

// Login


router.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    const usuario = await Usuario.findOne({ email });
    if (!usuario) {
      return res.status(400).json({ msg: "E-mail não encontrado" });
    }

    const senhaValida = await usuario.verificarSenha(senha);
    if (!senhaValida) {
      return res.status(400).json({ msg: "Senha incorreta" });
    }

    const token = jwt.sign(
      { id: usuario._id, categoria: usuario.categoria },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      msg: "Login realizado com sucesso",
      token,
      usuario
    });
  } catch (err) {
    res.status(500).json({ msg: "Erro ao fazer login", erro: err.message });
  }
});



// Alterar senha
router.put("/recovery/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const { senhaAtual, novaSenha } = req.body;

    if (!senhaAtual || !novaSenha)
      return res.status(400).json({ msg: "Informe senha atual e nova senha" });

    const usuario = await Usuario.findOne({ email });
    if (!usuario)
      return res.status(404).json({ msg: "Usuário não encontrado" });

    // Comparar senha atual (texto puro) com hash do banco
    const senhaCorreta = await bcrypt.compare(senhaAtual, usuario.senha);
    if (!senhaCorreta)
      return res.status(401).json({ msg: "Senha atual incorreta" });

    // Atualizar senha (o pre('save') vai re-hashar)
    usuario.senha = await bcrypt.hash(novaSenha, 10);
    await usuario.save();


    res.json({ msg: "Senha alterada com sucesso" });
  } catch (err) {
    console.error("Erro ao alterar senha:", err);
    res.status(500).json({ msg: "Erro ao alterar senha", erro: err.message });
  }
});


export default router;
