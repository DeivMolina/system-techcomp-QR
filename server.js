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
    origin: ["http://localhost:3000", "https://app-techcomp-16ff4d30c364.herokuapp.com", "https://front-techcomp.rkcreativo.com.mx", "https://chromatographyservices.com"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true
}));
app.use(cookieParser());

const storage = multer.memoryStorage();
const upload = multer({ storage });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// development
//const serviceAccount = JSON.parse(fs.readFileSync('./firebase-service-account.json', 'utf8'));

// Production
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
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
});

const verifyUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ Error: "No te has autenticado" });
    }

    const token = authHeader.split(' ')[1]; // Eliminar 'Bearer ' del encabezado
    if (!token) {
        return res.status(401).json({ Error: "Token no proporcionado" });
    }

    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
        if (err) {
            return res.status(401).json({ Error: "Token inválido o expirado" });
        }
        req.userId = decoded.id;
        req.userName = decoded.name;
        req.userType = decoded.type;
        next();
    });
};

app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM login WHERE email = ?';
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.status(500).json({ Error: "Error al ingresar" });
        }
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    return res.status(500).json({ Error: "Error de contraseña" });
                }
                if (response) {
                    const user = data[0];
                    const token = jwt.sign(
                        { id: user.id, name: user.name, type: user.type },
                        "jwt-secret-key",
                        { expiresIn: '1d' }
                    );
                    return res.json({ 
                        Status: "Exito", 
                        name: user.name, 
                        type: user.type, 
                        token 
                    });
                } else {
                    return res.status(401).json({ Error: "Contraseña incorrecta" });
                }
            });
        } else {
            return res.status(404).json({ Error: "Este email no existe" });
        }
    });
});


app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: "Exito", id: req.userId, name: req.userName, type: req.userType });
});

app.post('/register', (req, res) => {
    const sql =
        'INSERT INTO login (name, email, password, distributor, region, type) VALUES (?, ?, ?, ?, ?, ?)';

    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: 'Error cifrar contraseña' });

        const values = [
        req.body.name,
        req.body.email,
        hash,
        req.body.distributor || null, // distributor desde el body
        req.body.region || null,      // region desde el body
        req.body.type
        ];

        db.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            return res.json({ Error: 'Insertar datos en el servidor' });
        }
        return res.json({ Status: 'Exito' });
        });
    });
});


// Verificacion de Logout
app.get('/logout', (req, res) => {
    // Limpiar cookies si existen
    res.clearCookie('token', { path: '/' });

    // Respuesta al cliente
    return res.json({ Status: "Exito", Message: "Sesión cerrada correctamente" });
});


app.get('/report/:sku', (req, res) => {
    const sku = req.params.sku;

    const reportQuery = `SELECT * FROM reports WHERE sku = ?`;

    db.query(reportQuery, [sku], (err, reportResult) => {
        if (err) return res.status(500).json({ Error: 'Error al obtener el reporte' });
        if (reportResult.length === 0) return res.status(404).json({ Error: 'Modelo no encontrado' });

        const report = reportResult[0];

        const sendReport = () => {
            if (report.brand === 'Scion Instruments' && report.model === 'LC6000') {
                const modulesQuery = `SELECT * FROM modules WHERE report_id = ?`;
                db.query(modulesQuery, [report.id], (err, modulesResult) => {
                    if (err) return res.status(500).json({ Error: 'Error al obtener módulos' });
                    return res.status(200).json({
                        Status: 'Exito',
                        Report: report,
                        Modules: modulesResult,
                        isPublic: report.image_uploaded === 1
                    });
                });
            } else {
                const channelsQuery = `SELECT * FROM channels WHERE report_id = ?`;
                const samplersQuery = `SELECT * FROM samplers WHERE report_id = ?`;

                db.query(channelsQuery, [report.id], (err, channelsResult) => {
                    if (err) return res.status(500).json({ Error: 'Error al obtener canales' });

                    db.query(samplersQuery, [report.id], (err, samplersResult) => {
                        if (err) return res.status(500).json({ Error: 'Error al obtener samplers' });

                        return res.status(200).json({
                            Status: 'Exito',
                            Report: report,
                            Channels: channelsResult,
                            Samplers: samplersResult,
                            isPublic: report.image_uploaded === 1
                        });
                    });
                });
            }
        };

        if (report.image_uploaded === 1) {
            // ✅ Sin autenticación
            return sendReport();
        } else {
            // 🔒 Requiere autenticación
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({ Error: "Se requiere autenticación de lado del backend", AuthRequired: true });
            }

            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).json({ Error: "Token no proporcionado", AuthRequired: true });
            }

            jwt.verify(token, "jwt-secret-key", (err, decoded) => {
                if (err) {
                    return res.status(401).json({ Error: "Token inválido", AuthRequired: true });
                }

                // ✅ Autenticado
                return sendReport();
            });
        }
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

app.post('/report/complete/:sku', verifyUser, (req, res) => {
    const sku = req.params.sku;
    console.log('SKU recibido:', sku);

    // Log para revisar los datos que llegan al backend
    console.log('Body de la solicitud:', req.body);

    const {
        serialNumber,
        model,
        brand,
        serviceDate,
        serviceType,
        generalDescription,
        channels,
        samplers,
        image_name,
        user_id,
        engineerName,
        Organizer,
        Pump,
        AutoSampler,
        ColumnOven,
        Detectors,
    } = req.body;

    // Actualizar la tabla `reports`
    const updateReportSql = `
        UPDATE reports
        SET 
            image_name = ?, 
            upload_date = NOW(), 
            image_uploaded = 1, 
            user_id = ?, 
            serialNumber = ?, 
            model = ?, 
            brand = ?, 
            service_date = ?, 
            service_type = ?, 
            general_description = ?, 
            engineer_name = ?,
            model_id = NULL
        WHERE sku = ?
    `;

    const reportParams = [
        image_name,
        user_id,
        serialNumber,
        model,
        brand,
        serviceDate,
        serviceType,
        generalDescription,
        engineerName,
        sku
    ];

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

            if (model === 'LC6000') {
                // Desestructurar las propiedades desde req.body
                const {
                    Organizer,
                    Organizer_serial_number,
                    Pump,
                    Pump_serial_number,
                    AutoSampler,
                    AutoSampler_serial_number,
                    ColumnOven,
                    ColumnOven_serial_number,
                    Detectors,
                } = req.body;

                const insertModulesSql = `
                    INSERT INTO modules (report_id, module_name, module_value, module_serial_number)
                    VALUES ?
                `;
            
                // Construir los valores de los módulos principales
                const moduleValues = [
                    [reportId, 'Organizer', Organizer || 'NONE', Organizer_serial_number || null],
                    [reportId, 'Pump', Pump || 'NONE', Pump_serial_number || null],
                    [reportId, 'AutoSampler', AutoSampler || 'NONE', AutoSampler_serial_number || null],
                    [reportId, 'ColumnOven', ColumnOven || 'NONE', ColumnOven_serial_number || null],
                ];
            
                // Procesar detectores
                if (Detectors && Array.isArray(Detectors) && Detectors.length > 0) {
                    Detectors.forEach((detector) => {
                        moduleValues.push([
                            reportId,
                            'Detector',
                            detector.name || 'NONE', // Convertir nombre a texto
                            detector.serial_number || null, // Agregar el número de serie
                        ]);
                    });
                }

                console.log("Valores a insertar en la base de datos:", moduleValues); // Depuración
            
                // Insertar datos en la base de datos
                db.query(insertModulesSql, [moduleValues], (err) => {
                    if (err) {
                        console.error('Error al insertar módulos:', err);
                        return res.status(500).json({ Error: 'Error al insertar los módulos en la base de datos.' });
                    }
            
                    console.log('Módulos insertados con éxito.');
                    return res.status(200).json({
                        Status: 'Exito',
                        Message: 'Reporte y módulos actualizados con éxito.',
                    });
                });
            }   else {
                // Manejar otros modelos
                const insertChannelSql = `
                    INSERT INTO channels (report_id, channel_title, injector, detector, detector_serial_number, column_pn, column_description)
                    VALUES ?
                `;

                const channelValues = channels.map((channel) => [
                    reportId,
                    channel.canal,
                    channel.inyector,
                    channel.detector,
                    channel.serialNumber,
                    channel.columnPart,
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

                const insertSamplerSql = `
                    INSERT INTO samplers (report_id, sampler_type, sampler_name, sampler_serial_number, sampler_description)
                    VALUES ?
                `;

                const samplerValues = samplers.map((samplerItem) => [
                    reportId,
                    samplerItem.type,
                    samplerItem.otherSampler || null,
                    samplerItem.serialNumber,
                    samplerItem.description,
                ]);
                
                if (samplerValues.length > 0) {
                    db.query(insertSamplerSql, [samplerValues], (err) => {
                        if (err) {
                            console.error('Error al insertar samplers:', err);
                            return res.status(500).json({ Error: 'Error al insertar los samplers en la base de datos.' });
                        }
                
                        console.log('Samplers insertados con éxito.');

                        return res.status(200).json({
                            Status: 'Exito',
                            Message: 'Reporte, canales y sampler actualizados con éxito.',
                        });
                    });
                }
            }
        });
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
        SELECT 
            r.sku, 
            r.upload_date, 
            r.image_name, 
            r.image_uploaded, 
            r.user_id, 
            l.name, 
            l.email, 
            l.type, 
            l.region
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

app.get('/dashboard/stats', verifyUser, (req, res) => {
    const sql = `
        SELECT 
        COUNT(DISTINCT user_id) AS totalUsers,
        SUM(CASE WHEN image_uploaded = 1 THEN 1 ELSE 0 END) AS totalUploaded,
        COUNT(*) AS totalReports
        FROM reports;
    `;

    db.query(sql, (err, result) => {
        if (err) {
        console.error(err);
        return res.status(500).json({ Error: 'Error al obtener estadísticas del dashboard' });
        }

        const row = result[0] || { totalUsers: 0, totalUploaded: 0, totalReports: 0 };

        return res.json({
        Status: 'Exito',
        totalUsers: row.totalUsers,
        totalUploaded: row.totalUploaded,
        totalReports: row.totalReports
        });
    });
});

// Obtener perfil del usuario autenticado
app.get('/profile', verifyUser, (req, res) => {
    const sql = `
        SELECT id, name, email, distributor, region, type
        FROM login
        WHERE id = ?
        LIMIT 1
    `;

    db.query(sql, [req.userId], (err, result) => {
        if (err) {
        console.error(err);
        return res.status(500).json({ Status: 'Error', Error: 'Error al obtener el perfil' });
        }

        if (result.length === 0) {
        return res.status(404).json({ Status: 'Error', Error: 'Usuario no encontrado' });
        }

        const user = result[0];

        return res.json({
        Status: 'Exito',
        Profile: {
            id: user.id,
            name: user.name,
            email: user.email,
            distributor: user.distributor,
            region: user.region,
            type: user.type
        }
        });
    });
});

// Activity del usuario: reports relacionados al usuario autenticado
// Activity del usuario: reports relacionados al usuario autenticado
app.get('/profile/activity', verifyUser, (req, res) => {
    const sql = `
        SELECT 
        r.id,
        r.sku,
        r.upload_date,
        r.image_uploaded,
        r.user_id,
        l.name,
        l.email,
        l.region
        FROM reports r
        JOIN login l ON r.user_id = l.id
        WHERE r.user_id = ?
        ORDER BY r.upload_date DESC
    `;

    db.query(sql, [req.userId], (err, result) => {
        if (err) {
        console.error(err);
        return res
            .status(500)
            .json({ Status: 'Error', Error: 'Error al obtener la actividad del usuario' });
        }

        return res.json({
        Status: 'Exito',
        Activity: result
        });
    });
});

// Listado de usuarios (solo admin)
app.get('/users', verifyUser, (req, res) => {
  // si limitas a admin:
  // if (req.userType !== 'admin') {
  //   return res.status(403).json({ Status: 'Error', Error: 'Not authorized' });
  // }

  const sql = `
    SELECT 
      id,
      name,
      email,
      distributor,
      region,
      type
    FROM login
    ORDER BY name ASC
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      return res
        .status(500)
        .json({ Status: 'Error', Error: 'Error fetching users' });
    }

    return res.json({
      Status: 'Exito',
      Users: result
    });
  });
});

// Actualizar usuario
app.put('/users/:id', verifyUser, (req, res) => {
    // Opcional: solo admin
    if (req.userType !== 'admin') {
        return res.status(403).json({ Status: 'Error', Error: 'Not authorized' });
    }

    const { name, email, distributor, region, type } = req.body;
    const userId = req.params.id;

    const sql = `
        UPDATE login
        SET name = ?, email = ?, distributor = ?, region = ?, type = ?
        WHERE id = ?
    `;

    db.query(
        sql,
        [name, email, distributor || null, region || null, type, userId],
        (err, result) => {
        if (err) {
            console.error(err);
            return res
            .status(500)
            .json({ Status: 'Error', Error: 'Error updating user' });
        }

        return res.json({ Status: 'Exito' });
        }
    );
});

// Eliminar usuario
app.delete('/users/:id', verifyUser, (req, res) => {
  // Opcional: solo admin
  if (req.userType !== 'admin') {
    return res.status(403).json({ Status: 'Error', Error: 'Not authorized' });
  }

  const userId = req.params.id;

  // Primero eliminar reports asociados (si existen)
  const deleteReportsSql = 'DELETE FROM reports WHERE user_id = ?';
  db.query(deleteReportsSql, [userId], (err) => {
    if (err) {
      console.error('Error deleting user reports:', err);
      return res
        .status(500)
        .json({ Status: 'Error', Error: 'Error deleting user reports' });
    }

    // Ahora sí eliminar el usuario
    const deleteUserSql = 'DELETE FROM login WHERE id = ?';
    db.query(deleteUserSql, [userId], (err2, result2) => {
      if (err2) {
        console.error('Error deleting user:', err2);
        return res
          .status(500)
          .json({ Status: 'Error', Error: 'Error deleting user' });
      }

      // Si no se afectó ninguna fila, el usuario no existía
      if (result2.affectedRows === 0) {
        return res
          .status(404)
          .json({ Status: 'Error', Error: 'User not found' });
      }

      return res.json({ Status: 'Exito' });
    });
  });
});









const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Servidor levantado en ${PORT}`);
});
