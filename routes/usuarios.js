
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


// Rota para solicitar recuperação
router.post("/recovery/request", async (req, res) => {
  const { email } = req.body;

  // Busca o usuário pelo email
  const usuario = await Usuario.findOne({ email });
  
  // Se o usuário não for encontrado
  if (!usuario) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }

   // Se o usuário for encontrado, informamos que o processo de recuperação está em andamento
  res.json({
    msg: "Estamos recuperando sua senha. Verifique seu email (simulado) em breve.",
  });

});


// Rota para confirmar recuperação
router.put("/recovery/confirm", async (req, res) => {
  const { token, novaSenha } = req.body;

  if (!token || !novaSenha)
    return res.status(400).json({ msg: "Token e nova senha são obrigatórios" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "segredo-super-seguro");
    const usuario = await Usuario.findById(decoded.id);
    if (!usuario) return res.status(404).json({ msg: "Usuário não encontrado" });

    usuario.senha = await bcrypt.hash(novaSenha, 10);
    await usuario.save();

    res.json({ msg: "Senha alterada com sucesso" });
  } catch (err) {
    res.status(400).json({ msg: "Token inválido ou expirado" });
  }
});



export default router;
