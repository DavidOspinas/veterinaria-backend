import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

export const db = await mysql.createPool({
  host: "localhost",
  user: "root",
  password: "1234",  // pon tu contraseña si tienes
  database: "veterinaria_ica"
});
