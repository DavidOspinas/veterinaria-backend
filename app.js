import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";
import { db } from "./db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { verificarToken, verificarRol } from "./middlewareAuth.js";

dotenv.config();

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
// 🔥 CONFIG
// =====================================
const app = express();
app.use(cors());
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
// 🔥 LOGIN GOOGLE
// =====================================
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;

    const ticket = await client.verifyIdToken({
      idToken: credential,
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
    console.error(err);
    res.status(401).json({ ok: false, msg: "Token inválido" });
  }
});


// ==============================
// 🔥 LISTAR USUARIOS (ADMIN)
// ==============================
app.get("/api/usuarios", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, nombre, email FROM usuarios ORDER BY id DESC"
    );

    res.json({ ok: true, usuarios: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error al obtener usuarios" });
  }
});


// =====================================
// 🔥 ADMIN – CRUD VETERINARIOS
// =====================================
app.post("/api/veterinarios", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  try {
    const { usuario_id, especialidad, telefono } = req.body;

    const [user] = await db.query(
      "SELECT nombre, email FROM usuarios WHERE id = ?",
      [usuario_id]
    );

    if (user.length === 0)
      return res.json({ ok: false, msg: "Usuario no encontrado" });

    const { nombre, email } = user[0];

    const [result] = await db.query(
      "INSERT INTO veterinarios (usuario_id, nombre, email, especialidad, telefono) VALUES (?, ?, ?, ?, ?)",
      [usuario_id, nombre, email, especialidad, telefono]
    );

    res.json({ ok: true, id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error al crear veterinario" });
  }
});

app.get("/api/veterinarios", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  const [rows] = await db.query("SELECT * FROM veterinarios");
  res.json({ ok: true, veterinarios: rows });
});

// 🔥 contar citas de un veterinario
app.get("/api/veterinarios/:id/citas-count", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await db.query(
      "SELECT COUNT(*) AS total FROM citas WHERE veterinario_id = ?",
      [id]
    );

    res.json({ ok: true, total: rows[0].total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error obteniendo cantidad de citas" });
  }
});

// =====================================
// 🔥 ADMIN – CRUD MASCOTAS
// =====================================
app.post("/api/mascotas", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  try {
    const { usuario_id, nombre, especie, raza, edad, peso } = req.body;

    const [result] = await db.query(
      "INSERT INTO mascotas (usuario_id, nombre, especie, raza, edad, peso) VALUES (?, ?, ?, ?, ?, ?)",
      [usuario_id, nombre, especie, raza, edad, peso]
    );

    res.json({ ok: true, id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error al crear mascota" });
  }
});

app.get("/api/mascotas", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  const [rows] = await db.query(`
    SELECT m.*, u.nombre AS dueño
    FROM mascotas m
    JOIN usuarios u ON m.usuario_id = u.id
    ORDER BY m.id DESC
  `);

  res.json({ ok: true, mascotas: rows });
});

// =====================================
// 🔥 CLIENTE — MASCOTAS
// =====================================
app.get("/api/cliente/mascotas/:usuario_id", verificarToken, async (req, res) => {
  try {
    const { usuario_id } = req.params;

    const [rows] = await db.query(
      "SELECT * FROM mascotas WHERE usuario_id = ? ORDER BY creado_en DESC",
      [usuario_id]
    );

    res.json({ ok: true, mascotas: rows });
  } catch (err) {
    console.error("Error cargando mascotas cliente:", err);
    res.status(500).json({ ok: false, msg: "Error al obtener mascotas" });
  }
});

// =====================================
// 🔥 CLIENTE — CREAR MASCOTA
// =====================================
app.post("/api/cliente/mascotas", verificarToken, async (req, res) => {
  try {
    const { usuario_id, nombre, especie, raza, edad, peso } = req.body;

    const [result] = await db.query(
      `INSERT INTO mascotas (usuario_id, nombre, especie, raza, edad, peso)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [usuario_id, nombre, especie, raza, edad, peso]
    );

    res.json({ ok: true, msg: "Mascota registrada", id: result.insertId });

  } catch (err) {
    console.error("Error creando mascota cliente:", err);
    res.status(500).json({ ok: false, msg: "Error al crear mascota" });
  }
});

// =====================================
// 🔥 CLIENTE — CITAS
// =====================================
app.get("/api/cliente/citas/:usuario_id", verificarToken, async (req, res) => {
  try {
    const { usuario_id } = req.params;

    const [rows] = await db.query(
      `SELECT c.*, m.nombre AS mascota, v.nombre AS veterinario
       FROM citas c
       JOIN mascotas m ON m.id = c.mascota_id
       JOIN veterinarios v ON v.id = c.veterinario_id
       WHERE m.usuario_id = ?
       ORDER BY c.fecha DESC`,
      [usuario_id]
    );

    res.json({ ok: true, citas: rows });
  } catch (err) {
    console.error("Error cargando citas cliente:", err);
    res.status(500).json({ ok: false, msg: "Error al obtener citas" });
  }
});

// =====================================
// 🔥 CLIENTE — CREAR CITA
// =====================================
app.post("/api/cliente/citas", verificarToken, async (req, res) => {
  try {
    const { mascota_id, veterinario_id, fecha, motivo } = req.body;

    if (!mascota_id || !veterinario_id || !fecha || !motivo) {
      return res.json({ ok: false, msg: "Faltan datos para crear la cita" });
    }

    const [result] = await db.query(
      "INSERT INTO citas (mascota_id, veterinario_id, fecha, motivo, estado) VALUES (?, ?, ?, ?, 'PENDIENTE')",
      [mascota_id, veterinario_id, fecha, motivo]
    );

    res.json({
      ok: true,
      msg: "Cita creada correctamente",
      id: result.insertId
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, msg: "Error al crear cita" });
  }
});

// =====================================
// 🔥 ADMIN — CITAS
// =====================================
app.get("/api/citas", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT c.id, m.nombre AS mascota, v.nombre AS veterinario, c.fecha, c.motivo
      FROM citas c
      JOIN mascotas m ON c.mascota_id = m.id
      JOIN veterinarios v ON c.veterinario_id = v.id
      ORDER BY c.id DESC
    `);

    res.json({ ok: true, citas: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "Error al obtener citas" });
  }
});

app.delete("/api/citas/:id", verificarToken, verificarRol("ADMIN"), async (req, res) => {
  const { id } = req.params;
  await db.query("DELETE FROM citas WHERE id = ?", [id]);
  res.json({ ok: true, msg: "Cita eliminada" });
});

// =====================================
// 🔥 VETERINARIOS PUBLICOS (CLIENTE)
// =====================================
app.get("/api/public/veterinarios", verificarToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, nombre, especialidad FROM veterinarios"
    );

    res.json({ ok: true, veterinarios: rows });

  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, msg: "Error al obtener veterinarios" });
  }
});

// =====================================
// 🔥 INICIAR SERVIDOR
// =====================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en el puerto ${PORT}`);
});


