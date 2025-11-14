import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const UsuarioSchema = new mongoose.Schema(
  {
    nome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
    categoria: { type: String, default: "cuidador" },
  },
  { timestamps: true }
);


// Método para verificar senha
UsuarioSchema.methods.verificarSenha = async function (senhaDigitada) {
  return await bcrypt.compare(senhaDigitada, this.senha);
};

export default mongoose.model("Usuario", UsuarioSchema);

