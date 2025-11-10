import bcrypt from "bcrypt";
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
    const user = await Usuario.findOne({ email });

    if (!user)
      return res.status(401).json({ msg: "Usuário não encontrado" });

    const senhaCorreta = await bcrypt.compare(senha, user.senha);
    if (!senhaCorreta)
      return res.status(401).json({ msg: "Senha incorreta" });

    // só gera token depois que a senha é validada
    const token = gerarToken(user);

    res.json({ usuario: user, token });
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
    usuario.senha = novaSenha;
    await usuario.save();

    res.json({ msg: "Senha alterada com sucesso" });
  } catch (err) {
    console.error("Erro ao alterar senha:", err);
    res.status(500).json({ msg: "Erro ao alterar senha", erro: err.message });
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

    // Criptografar nova senha antes de salvar
    const novaSenhaHash = await bcrypt.hash(novaSenha, 10);
    usuario.senha = novaSenhaHash;
    await usuario.save();

    res.json({ msg: "Senha alterada com sucesso" });
  } catch (err) {
    console.error("Erro ao alterar senha:", err);
    res.status(500).json({ msg: "Erro ao alterar senha", erro: err.message });
  }
});


export default router;
