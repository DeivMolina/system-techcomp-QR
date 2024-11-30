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
import fs from 'fs';
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

// const serviceAccount = JSON.parse(fs.readFileSync('./firebase-service-account.json', 'utf8'));
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
        return res.status(401).json({ Error: "No te has autentificado Backend" });
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
    return res.json({ Status: "Exito", id: req.userId, name: req.userName, type: req.userType });
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

app.get('/report/:sku', (req, res) => {
    const sku = req.params.sku;

    // Query para obtener la información del reporte principal
    const reportQuery = `
        SELECT * FROM reports WHERE sku = ?
    `;

    // Query para obtener los canales relacionados con el reporte
    const channelsQuery = `
        SELECT * FROM channels WHERE report_id = (
            SELECT id FROM reports WHERE sku = ?
        )
    `;

    // Query para obtener el sampler relacionado con el reporte
    const samplerQuery = `
        SELECT * FROM samplers WHERE report_id = (
            SELECT id FROM reports WHERE sku = ?
        )
    `;

    db.query(reportQuery, [sku], (err, reportResult) => {
        if (err) {
            console.error('Error al obtener el reporte:', err);
            return res.status(500).json({ Error: 'Error al obtener el reporte' });
        }

        if (reportResult.length === 0) {
            return res.status(404).json({ Error: 'Este modelo no está en la base de datos' });
        }

        const report = reportResult[0];

        // Obtener los canales
        db.query(channelsQuery, [sku], (err, channelsResult) => {
            if (err) {
                console.error('Error al obtener los canales:', err);
                return res.status(500).json({ Error: 'Error al obtener los canales' });
            }

            // Obtener el sampler
            db.query(samplerQuery, [sku], (err, samplerResult) => {
                if (err) {
                    console.error('Error al obtener el sampler:', err);
                    return res.status(500).json({ Error: 'Error al obtener el sampler' });
                }

                // Responder con toda la información
                return res.status(200).json({
                    Status: 'Exito',
                    Report: report,
                    Channels: channelsResult,
                    Sampler: samplerResult.length > 0 ? samplerResult[0] : null,
                });
            });
        });
    });
});

app.post('/report/upload-temp/:sku', verifyUser, upload.any(), (req, res) => {
    const sku = req.params.sku;
    const file = req.files[0];
    const userId = req.userId;

    if (!file) {
        return res.json({ Error: "Por favor seleccione un archivo" });
    }

    // Validar el tipo de archivo
    const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg'];
    if (!allowedTypes.includes(file.mimetype)) {
        return res.json({ Error: "Tipo de archivo no permitido. Solo se permiten archivos .png, .jpg y .jpeg" });
    }

    const filename = `${sku}-${file.originalname}`;
    const fileBuffer = file.buffer;

    // Subir la imagen a Firebase Storage
    const fileUpload = bucket.file(filename);
    const stream = fileUpload.createWriteStream({
        metadata: {
            contentType: file.mimetype,
        },
    });

    stream.on('error', (err) => {
        return res.json({ Error: "Error al subir la imagen a Firebase Storage" });
    });

    stream.on('finish', () => {
        fileUpload.makePublic().then(() => {
            const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filename}`;
            return res.json({
                Status: "Exito",
                imageUrl,
                filename,
                message: "Imagen cargada en Firebase Storage",
            });
        });
    });

    stream.end(fileBuffer);
});

app.post('/report/complete/:sku', verifyUser, async (req, res) => {
    const sku = req.params.sku;

    // Log para revisar los datos que llegan al backend
    console.log('Body de la solicitud:', req.body);

    // Verificar si los datos están presentes en el cuerpo de la solicitud
    if (!req.body || !req.body.reports || !req.body.channels || !req.body.samplers) {
        console.error('Faltan datos en el cuerpo de la solicitud.');
        return res.status(400).json({ Error: 'Faltan datos en la solicitud.' });
    }

    const {
        reports: {
            image_name,
            image_uploaded,
            user_id,
            model_id,
            serialNumber,
            serviceDate,
            serviceType,
            generalDescription,
        },
        channels,
        samplers,
    } = req.body;

    try {
        // Actualizar la tabla `reports`
        const updateReportSql = `
            UPDATE reports
            SET 
                image_name = ?, 
                upload_date = NOW(), 
                image_uploaded = ?, 
                user_id = ?, 
                model_id = ?, 
                serialNumber = ?, 
                service_date = ?, 
                service_type = ?, 
                general_description = ?
            WHERE sku = ?
        `;

        const reportParams = [
            image_name,
            image_uploaded,
            user_id,
            model_id,
            serialNumber,
            serviceDate,
            serviceType,
            generalDescription,
            sku,
        ];

        console.log('Ejecutando consulta SQL para reportes con parámetros:', reportParams);

        // Ejecutar la actualización del reporte
        db.query(updateReportSql, reportParams, (err, result) => {
            if (err) {
                console.error('Error al actualizar la tabla reports:', err);
                return res.status(500).json({ Error: 'Error al actualizar el reporte en la base de datos.' });
            }

            if (result.affectedRows === 0) {
                console.error('No se encontró el SKU en la base de datos.');
                return res.status(404).json({ Error: 'No se encontró el SKU en la base de datos.' });
            }

            // Obtener el ID del reporte actualizado
            const getReportIdSql = `SELECT id FROM reports WHERE sku = ?`;
            db.query(getReportIdSql, [sku], (err, results) => {
                if (err) {
                    console.error('Error al obtener el ID del reporte:', err);
                    return res.status(500).json({ Error: 'Error al obtener el ID del reporte.' });
                }

                const reportId = results[0]?.id;

                if (!reportId) {
                    console.error('No se encontró el ID del reporte después de la actualización.');
                    return res.status(404).json({ Error: 'No se encontró el reporte después de la actualización.' });
                }

                console.log('ID del reporte obtenido:', reportId);

                // Insertar canales
                const insertChannelSql = `
                    INSERT INTO channels (report_id, channel_number, injector, detector, detector_serial_number, column_pn, column_description)
                    VALUES ?
                `;

                const channelValues = channels.map((channel, index) => [
                    reportId,
                    index + 1, // channel_number basado en el índice del canal
                    channel.injector,
                    channel.detector,
                    channel.detectorSerialNumber,
                    channel.columnPN,
                    channel.columnDescription,
                ]);

                if (channelValues.length > 0) {
                    db.query(insertChannelSql, [channelValues], (err) => {
                        if (err) {
                            console.error('Error al insertar canales:', err);
                            return res.status(500).json({ Error: 'Error al insertar canales en la base de datos.' });
                        }

                        console.log('Canales insertados con éxito.');
                    });
                }

                // Insertar sampler
                const insertSamplerSql = `
                    INSERT INTO samplers (report_id, sampler_type , sampler_serial_number)
                    VALUES (?, ?, ?)
                `;

                const samplerValues = [
                    reportId,
                    samplers.type,
                    samplers.serialNumber,
                ];

                db.query(insertSamplerSql, samplerValues, (err) => {
                    if (err) {
                        console.error('Error al insertar sampler:', err);
                        return res.status(500).json({ Error: 'Error al insertar el sampler en la base de datos.' });
                    }

                    console.log('Sampler insertado con éxito.');

                    // Respuesta exitosa
                    res.status(200).json({
                        Status: 'Exito',
                        Message: 'Reporte, canales y sampler actualizados con éxito.',
                        imageUrl: `https://storage.googleapis.com/${bucket.name}/${image_name}`,
                    });
                });
            });
        });
    } catch (err) {
        console.error('Error general en el servidor:', err);
        res.status(500).json({ Error: 'Error al procesar la solicitud.' });
    }
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
        SELECT r.sku, r.upload_date, r.image_name, r.image_uploaded, r.user_id, l.name, l.email, l.type 
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Servidor levantado en ${PORT}`);
});
