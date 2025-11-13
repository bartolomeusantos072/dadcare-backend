import mongoose from "mongoose";
import bcrypt from "bcrypt";

const UsuarioSchema = new mongoose.Schema(
  {
    nome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
    categoria: { type: String, default: "cuidador" },
  },
  { timestamps: true }
);

// Antes de salvar, se a senha foi modificada, gera o hash
UsuarioSchema.pre("save", async function (next) {
  // Se a senha não foi modificada, apenas continua.
  if (!this.isModified("senha")) return next();

  // Se a senha for um hash válido, não gere novo hash
  if (bcrypt.isValid(this.senha)) return next();

  const salt = await bcrypt.genSalt(10);
  this.senha = await bcrypt.hash(this.senha, salt);
  next();
});

// Método para verificar senha
UsuarioSchema.methods.verificarSenha = async function (senhaDigitada) {
  return await bcrypt.compare(senhaDigitada, this.senha);
};

export default mongoose.model("Usuario", UsuarioSchema);

