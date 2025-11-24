import jwt from "jsonwebtoken";
import { db } from "./db.js";

// ================================================
// 🟦 VERIFICAR TOKEN (Función global)
// ================================================
export function verificarToken(req, res, next) {
  const header = req.headers["authorization"];

  if (!header) {
    return res.status(401).json({ ok: false, msg: "Token no enviado" });
  }

  // Quitar "Bearer "
  const token = header.replace("Bearer ", "");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 🔥 Estandarizado: SIEMPRE será req.user
    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ ok: false, msg: "Token inválido" });
  }
}


// ================================================
// 🟧 VERIFICAR ROL (ADMIN, CLIENTE, etc)
// ================================================
export function verificarRol(rolNecesario) {
  return async function (req, res, next) {
    try {
      // 🔥 Cambiado: antes era req.usuario
      const usuarioId = req.user.id;

      const [roles] = await db.query(
        `SELECT r.nombre 
         FROM usuarios_roles ur
         JOIN roles r ON ur.rol_id = r.id
         WHERE ur.usuario_id = ?`,
        [usuarioId]
      );

      const tieneRol = roles.some(r => r.nombre === rolNecesario);

      if (!tieneRol) {
        return res.status(403).json({
          ok: false,
          msg: "No tienes permisos para esta acción",
        });
      }

      next();
    } catch (err) {
      console.error("Error en verificarRol:", err);
      return res.status(500).json({ ok: false, msg: "Error interno" });
    }
  };
}
