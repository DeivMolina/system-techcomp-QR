import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';

const salt = 10;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000", "https://app-techcomp-16ff4d30c364.herokuapp.com", "https://front-techcomp.rkcreativo.com.mx"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

const storage = multer.memoryStorage();
const upload = multer({ storage });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "app-techcomp.appspot.com"
});

const bucket = admin.storage().bucket();

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ Error: "No te has autentificado" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.status(401).json({ Error: "Token no es correcto" });
            } else {
                req.userId = decoded.id;
                req.userName = decoded.name;
                req.userType = decoded.type;
                next();
            }
        });
    }
};

app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM login WHERE email = ?';
    console.log("Intentando iniciar sesión con el email:", req.body.email);
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            console.log("Error al realizar la consulta a la base de datos:", err);
            return res.json({ Error: "Error al ingresar" });
        }
        if (data.length > 0) {
            console.log("Usuario encontrado:", data[0]);
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    console.log("Error al comparar la contraseña:", err);
                    return res.json({ Error: "Error de contraseña" });
                }
                if (response) {
                    const user = data[0];
                    const token = jwt.sign({ id: user.id, name: user.name, type: user.type }, "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token, { httpOnly: true, sameSite: 'None', secure: true });
                    return res.json({ Status: "Exito", name: user.name, type: user.type, token });
                } else {
                    console.log("Contraseña incorrecta");
                    return res.json({ Error: "Contraseña Incorrecta" });
                }
            });
        } else {
            console.log("Email no encontrado");
            return res.json({ Error: "Este email no existe" });
        }
    });
});

app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: "Exito", name: req.userName, type: req.userType });
});

app.post('/register', (req, res) => {
    const sql = "INSERT INTO login (name, email, password, type) VALUES (?, ?, ?, ?)";
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error cifrar contraseña" });
        const values = [
            req.body.name,
            req.body.email,
            hash,
            req.body.type
        ];
        db.query(sql, values, (err, result) => {
            if (err) return res.json({ Error: "Insertar datos en el servidor" });
            return res.json({ Status: "Exito" });
        });
    });
});

// Verificacion de Logout
app.get('/logout', (req, res) => {
    res.clearCookie('token', { path: '/' });
    return res.json({ Status: "Exito" });
});

app.get('/report/:sku', verifyUser, (req, res) => {
    const sku = req.params.sku;
    const sql = 'SELECT * FROM reports WHERE sku = ?';
    db.query(sql, [sku], (err, data) => {
        if (err) return res.json({ Error: "Error al verificar el Folio" });
        if (data.length > 0) {
            return res.json({ Status: "Exito", Report: data[0] });
        } else {
            return res.json({ Error: "Este modelo no está en la base de datos" });
        }
    });
});

app.post('/report/upload/:sku', verifyUser, upload.any(), (req, res) => {  // Acepta cualquier archivo con cualquier campo de nombre
    console.log("Ruta de subida de archivos llamada");
    const sku = req.params.sku;
    const file = req.files[0];  // Obtén el primer archivo
    const userId = req.userId;

    if (!file) {
        console.log("No se subió ningún archivo");
        return res.json({ Error: "Por favor seleccione un archivo" });
    }

    // Validar el tipo de archivo
    const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg'];
    if (!allowedTypes.includes(file.mimetype)) {
        return res.json({ Error: "Tipo de archivo no permitido. Solo se permiten archivos .png, .jpg y .jpeg" });
    }

    console.log("Archivo subido:", file);
    const filename = `${sku}-${Date.now()}-${file.originalname}`;
    const fileBuffer = file.buffer;

    console.log("Actualizando la base de datos...");
    const sql = 'UPDATE reports SET image_name = ?, upload_date = NOW(), image_uploaded = 1, user_id = ? WHERE sku = ?';
    db.query(sql, [filename, userId, sku], (err, result) => {
        if (err) {
            console.log("Error al actualizar la base de datos", err);
            return res.json({ Error: "Error al actualizar la base de datos" });
        }

        console.log("Base de datos actualizada correctamente");

        // Subir la imagen a Firebase Storage
        const fileUpload = bucket.file(filename);
        const stream = fileUpload.createWriteStream({
            metadata: {
                contentType: file.mimetype
            }
        });

        stream.on('error', (err) => {
            console.log("Error al subir la imagen a Firebase Storage", err);
            return res.json({ Error: "Error al subir la imagen a Firebase Storage" });
        });

        stream.on('finish', () => {
            fileUpload.makePublic().then(() => {
                const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filename}`;

                // Actualizar la base de datos con la URL de la imagen
                const sqlUpdate = 'UPDATE reports SET image_name = ?, image_uploaded = 1 WHERE sku = ?';
                db.query(sqlUpdate, [filename, sku], (err, result) => {
                    if (err) {
                        console.log("Error al actualizar la URL de la imagen en la base de datos", err);
                        return res.json({ Error: "Error al actualizar la URL de la imagen en la base de datos" });
                    }
                    console.log("URL de la imagen actualizada en la base de datos correctamente");
                    return res.json({ Status: "Exito", filename });
                });
            });
        });

        stream.end(fileBuffer);
    });
});

app.get('/admin/reports', verifyUser, (req, res) => {
    if (req.userType !== 'admin') {
        return res.status(403).json({ Error: "Acceso denegado" });
    }

    const sql = `
        SELECT r.sku, r.upload_date, r.image_name, r.image_uploaded, r.distributor, r.user_id, l.name, l.email, l.type 
        FROM reports r 
        JOIN login l ON r.user_id = l.id
        ORDER BY r.upload_date DESC
    `;

    db.query(sql, (err, data) => {
        if (err) {
            console.log("Error al obtener los datos", err);
            return res.json({ Error: "Error al obtener los datos" });
        }
        return res.json({ Status: "Exito", Data: data });
    });
});

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Servidor levantado en ${PORT}`);
});
