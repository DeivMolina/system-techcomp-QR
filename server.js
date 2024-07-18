import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import axios from 'axios';
import FormData from 'form-data';
import path from 'path';

const salt = 10;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000", "https://app-techcomp-16ff4d30c364.herokuapp.com", "https://front-techcomp.rkcreativo.com.mx"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

const upload = multer({
    storage: multer.memoryStorage()
});

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
    db.query(sql, [req.body.email], (err, data) => {
        if (err) return res.json({ Error: "Error al ingresar" });
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) return res.json({ Error: "Error de contraseña" });
                if (response) {
                    const user = data[0];
                    const token = jwt.sign({ id: user.id, name: user.name, type: user.type }, "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token, { httpOnly: true, sameSite: 'None', secure: true });
                    return res.json({ Status: "Exito", name: user.name, type: user.type, token });
                } else {
                    return res.json({ Error: "Contraseña Incorrecta" });
                }
            });
        } else {
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
            req.body.type // Asegúrate de que el tipo de usuario se envíe en la solicitud de registro
        ];
        db.query(sql, values, (err, result) => {
            if (err) return res.json({ Error: "Insertar datos en el servidor" });
            return res.json({ Status: "Exito" });
        });
    });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
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

app.post('/report/upload/:sku', verifyUser, upload.single('file'), (req, res) => {
    const sku = req.params.sku;
    const file = req.file;
    const userId = req.userId;

    if (!file) {
        console.log("No se subió ningún archivo");
        return res.json({ Error: "Por favor seleccione un archivo" });
    }

    const filename = `${sku}-${file.originalname}`;
    const sql = 'UPDATE reports SET image_name = ?, upload_date = NOW(), image_uploaded = 1, user_id = ? WHERE sku = ?';

    // Actualizar la base de datos primero
    db.query(sql, [filename, userId, sku], (err, result) => {
        if (err) {
            console.log("Error al actualizar la base de datos", err);
            return res.json({ Error: "Error al actualizar la base de datos" });
        }

        // Subir la imagen al servidor externo
        const formData = new FormData();
        formData.append('file', file.buffer, filename);

        axios.post('https://front-techcomp.rkcreativo.com.mx/upload.php', formData, {
            headers: {
                ...formData.getHeaders()
            }
        })
        .then(response => {
            if (response.data.status === 'success') {
                const imageUrl = response.data.url; 

                // Actualizar la base de datos con la URL de la imagen
                const sqlUpdate = 'UPDATE reports SET image_name = ?, image_uploaded = 1 WHERE sku = ?';
                db.query(sqlUpdate, [imageUrl, sku], (err, result) => {
                    if (err) {
                        console.log("Error al actualizar la URL de la imagen en la base de datos", err);
                        return res.json({ Error: "Error al actualizar la URL de la imagen en la base de datos" });
                    }
                    console.log("Archivo subido y base de datos actualizada correctamente");
                    return res.json({ Status: "Exito", filename: imageUrl });
                });
            } else {
                return res.json({ Error: "Error al subir la imagen al servidor externo" });
            }
        })
        .catch(error => {
            console.log("Error al subir el archivo al servidor externo", error);
            return res.json({ Error: "Error al subir el archivo al servidor externo" });
        });
    });
});

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Servidor levantado en ${PORT}`);
});
