import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const salt = 10;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["https://app-techcomp-16ff4d30c364.herokuapp.com"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

// Asegúrate de que la carpeta 'uploads' exista
const uploadDir = path.join(path.resolve(), 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Configuración de Multer para la subida de archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const sku = req.params.sku;
        cb(null, `${sku}-${file.originalname}`);
    }
});

const upload = multer({ storage });

// Conexión a la base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Verificación de usuario-token-cookies
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ Error: "No te has autentificado" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.status(401).json({ Error: "Token no es correcto" });
            } else {
                req.name = decoded.name;
                next();
            }
        });
    }
};

// Acceso de usuario
app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM login WHERE email = ?';
    db.query(sql, [req.body.email], (err, data) => {
        if (err) return res.json({ Error: "Error al ingresar" });
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) return res.json({ Error: "Error de contraseña" });
                if (response) {
                    const name = data[0].name;
                    const token = jwt.sign({ name }, "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token, { httpOnly: true, sameSite: 'Lax' });
                    return res.json({ Status: "Exito" });
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
    return res.json({ Status: "Exito", name: req.name });
});

// Registro de usuario
app.post('/register', (req, res) => {
    const sql = "INSERT INTO login (name, email, password) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error cifrar contraseña" });
        const values = [
            req.body.name,
            req.body.email,
            hash
        ];
        db.query(sql, [values], (err, result) => {
            if (err) return res.json({ Error: "Insertar datos en el servidor" });
            return res.json({ Status: "Exito" });
        });
    });
});

// Cierre de sesión
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Exito" });
});

// Ruta para obtener el reporte por SKU
app.get('/report/:sku', verifyUser, (req, res) => {
    const sku = req.params.sku;
    const sql = 'SELECT * FROM reports WHERE sku = ?';
    db.query(sql, [sku], (err, data) => {
        if (err) return res.json({ Error: "Error al verificar el SKU" });
        if (data.length > 0) {
            return res.json({ Status: "Exito", Report: data[0] });
        } else {
            return res.json({ Error: "Este modelo no está en la base de datos" });
        }
    });
});

// Ruta para subir el archivo
app.post('/report/upload/:sku', verifyUser, upload.single('file'), (req, res) => {
    const sku = req.params.sku;
    const file = req.file;
    if (!file) {
        console.log("No se subió ningún archivo");
        return res.json({ Error: "Por favor seleccione un archivo" });
    }

    const sql = 'UPDATE reports SET image_name = ?, upload_date = NOW(), image_uploaded = 1 WHERE sku = ?';
    db.query(sql, [file.filename, sku], (err, result) => {
        if (err) {
            console.log("Error al subir el archivo", err);
            return res.json({ Error: "Error al subir el archivo" });
        }
        console.log("Archivo subido y base de datos actualizada correctamente");
        return res.json({ Status: "Exito", filename: file.filename });
    });
});

// Servir archivos estáticos desde la carpeta 'uploads'
app.use('/uploads', express.static(path.join(path.resolve(), 'uploads')));

// Puerto del servidor
const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Servidor levantado en ${PORT}`);
});
