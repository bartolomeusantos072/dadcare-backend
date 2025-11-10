import jwt from "jsonwebtoken";

const segredo = process.env.JWT_SECRET || "segredo-super-seguro";

export function gerarToken(usuario) {
  return jwt.sign(
    { id: usuario._id, email: usuario.email, categoria: usuario.categoria },
    segredo,
    { expiresIn: "8h" }
  );
}

export function autenticarToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "Token ausente" });

  try {
    const decoded = jwt.verify(token, segredo);
    req.usuario = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token inválido" });
  }
}
