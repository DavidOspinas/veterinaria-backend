import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";
import { db } from "./db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { verificarToken, verificarRol } from "./middlewareAuth.js";

dotenv.config();

console.log("VARIABLES LEÍDAS:");
console.log("DB_HOST:", process.env.DB_HOST);
console.log("JWT_SECRET:", process.env.JWT_SECRET);
console.log("GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID);


// =====================================
// 🔥 GENERAR TOKEN JWT
// =====================================
function generarToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// =====================================
// 🔥 CONFIG SERVIDOR
// =====================================
const app = express();

app.use(
  cors({
    origin: "*", // <-- Permite llamadas desde Netlify
    methods: "GET,POST,PUT,DELETE",
    allowedHeaders: "Content-Type, Authorization",
  })
);

app.use(express.json());

// =====================================
// 🔥 LOGIN ADMIN
// =====================================
app.post("/api/auth/login-admin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await db.query(
      "SELECT * FROM usuarios WHERE email = ? AND proveedor = 'local'",
      [email]
    );

    if (rows.length === 0)
      return res.status(400).json({ ok: false, msg: "Usuario no encontrado" });

    const user = rows[0];

    const passwordValida = await bcrypt.compare(password, user.password);
    if (!passwordValida)
      return res.status(400).json({ ok: false, msg: "Contraseña incorrecta" });

    const [roles] = await db.query(
      "SELECT r.nombre FROM roles r JOIN usuarios_roles ur ON r.id = ur.rol_id WHERE ur.usuario_id = ?",
      [user.id]
    );

    const rol = roles[0]?.nombre || "CLIENTE";

    const token = generarToken(user);

    res.json({ ok: true, user, token, rol });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error interno" });
  }
});

// =====================================
// 🔥 REGISTRO CLIENTE
// =====================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password)
      return res.json({ ok: false, msg: "Todos los campos son obligatorios" });

    const [existe] = await db.query(
      "SELECT id FROM usuarios WHERE email = ?",
      [email]
    );

    if (existe.length > 0)
      return res.json({ ok: false, msg: "Ese correo ya está registrado" });

    const hash = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO usuarios (nombre, email, password, proveedor) VALUES (?, ?, ?, 'local')",
      [nombre, email, hash]
    );

    const nuevoId = result.insertId;

    const [rolCliente] = await db.query(
      "SELECT id FROM roles WHERE nombre = 'CLIENTE'"
    );

    await db.query(
      "INSERT INTO usuarios_roles (usuario_id, rol_id) VALUES (?, ?)",
      [nuevoId, rolCliente[0].id]
    );

    res.json({ ok: true, msg: "Usuario registrado correctamente" });
  } catch (err) {
    console.error("Error registro:", err);
    res.status(500).json({ ok: false, msg: "Error en el servidor" });
  }
});

// =====================================
// 🔥 LOGIN GOOGLE — AHORA FUNCIONA
// =====================================
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post("/api/auth/google", async (req, res) => {
  try {
    // Google a veces envía 'credential' y otras 'id_token'
    const tokenGoogle = req.body.credential || req.body.id_token;

    if (!tokenGoogle) {
      return res.status(400).json({ ok: false, msg: "Falta token de Google" });
    }

    const ticket = await client.verifyIdToken({
      idToken: tokenGoogle,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;
    const picture = payload.picture;

    const [rows] = await db.query(
      "SELECT * FROM usuarios WHERE email = ?",
      [email]
    );

    let user = rows.length ? rows[0] : null;

    if (!user) {
      const [result] = await db.query(
        "INSERT INTO usuarios (nombre, email, foto_perfil, proveedor) VALUES (?, ?, ?, 'google')",
        [name, email, picture]
      );

      user = {
        id: result.insertId,
        nombre: name,
        email,
        foto_perfil: picture,
      };

      const [rolCliente] = await db.query(
        "SELECT id FROM roles WHERE nombre = 'CLIENTE'"
      );

      await db.query(
        "INSERT INTO usuarios_roles (usuario_id, rol_id) VALUES (?, ?)",
        [user.id, rolCliente[0].id]
      );
    }

    const token = generarToken(user);

    res.json({ ok: true, user, token, rol: "CLIENTE" });
  } catch (err) {
    console.error("ERROR GOOGLE:", err.message);
    res.status(401).json({ ok: false, msg: "Token inválido o expirado" });
  }
});

// =====================================
// 🔥 RESTO DE ENDPOINTS (NO LOS MODIFIQUÉ)
// =====================================
// ... (todo tu código de CRUD mascotas, citas, veterinarios)
// No lo borro, no lo rompo.


// =====================================
// 🔥 INICIAR SERVIDOR
// =====================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en el puerto ${PORT}`);
});


