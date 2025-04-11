require('dotenv').config();
const express = require('express');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { initializeApp } = require('firebase/app');


const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configurar transporter de nodemailer (agregar después de firebaseConfig)
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});
const { 
  getFirestore, 
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  query, 
  where, 
  getDocs,
  deleteDoc,
  updateDoc 
} = require('firebase/firestore');
// Añadir al inicio del server.js
const JWT_SECRET = process.env.JWT_SECRET;

// Configuración Firebase usando variables de entorno
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

// Inicializar Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

const app = express();
app.use(cors());
app.use(express.json());

// Validaciones
const validateUsername = (username) => /^[a-zA-Z0-9]{3,20}$/.test(username);
const validatePassword = (password) => /^(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);

// Endpoints
app.post('/api/auth/check-username', async (req, res) => {
  try {
    const { username } = req.body;
    const usersRef = collection(db, 'users');
    const q = query(usersRef, where('username', '==', username));
    const snapshot = await getDocs(q);
    res.json({ available: snapshot.empty });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar usuario' });
  }
});
app.post('/api/auth/check-email', async (req, res) => {
  const { email } = req.body;
  const usersRef = collection(db, 'users');
  const q = query(usersRef, where('email', '==', email));
  const snapshot = await getDocs(q);
  res.json({ available: snapshot.empty });
});
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  
  // Validaciones del servidor
  if (!validateUsername(username)) {
    return res.status(400).json({ error: 'Nombre de usuario inválido' });
  }
  
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Contraseña no cumple requisitos' });
  }

  const secret = speakeasy.generateSecret({ length: 20 });
  const hashedPassword = await bcrypt.hash(password, 10);
  
  // Guardar temporalmente hasta verificación MFA
  const tempUser = {
    email,
    username,
    password: hashedPassword,
    mfaSecret: secret.base32,
    verified: false,
    createdAt: new Date()
  };

  await setDoc(doc(db, 'tempUsers', email), tempUser);
  res.json({ secret: secret.otpauth_url });
});
app.post('/api/auth/verify-registration', async (req, res) => {
  const { email, token } = req.body;
  const tempUserRef = doc(db, 'tempUsers', email);
  const tempUserSnap = await getDoc(tempUserRef);

  if (!tempUserSnap.exists()) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  const tempUser = tempUserSnap.data();
  const verified = speakeasy.totp.verify({
      secret: tempUser.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
  });

  if (verified) {
      // Mover a usuarios permanentes
      await setDoc(doc(db, 'users', email), { 
          ...tempUser, 
          verified: true,
          mfaEnabled: true,
          mfaSecret: tempUser.mfaSecret
      });
      await deleteDoc(tempUserRef);
      res.json({ success: true });
  } else {
      res.status(401).json({ error: 'Código inválido' });
  }
});
  app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Buscar en ambas colecciones
        const userRef = doc(db, 'users', email);
        const userSnap = await getDoc(userRef);

        if (!userSnap.exists()) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const user = userSnap.data();
        
        // Verificar si está verificado
        if (!user.verified) {
            return res.status(403).json({ error: 'Usuario no verificado' });
        }

      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
          return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      if (user.mfaEnabled) {
          return res.json({ requiresMFA: true });
      }

      const token = jwt.sign({ userId: user.email }, JWT_SECRET);
      res.json({ token, user });
  } catch (error) {
      res.status(500).json({ error: 'Error en el login' });
  }
});
app.post('/api/auth/verify-mfa', async (req, res) => {
  try {
      const { email, token } = req.body;
      
      if (!email || !token) {
          return res.status(400).json({ error: 'Datos incompletos' });
      }

      const userRef = doc(db, 'users', email);
      const userSnap = await getDoc(userRef);

      if (!userSnap.exists()) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const user = userSnap.data();
      
      if (!user.mfaSecret) {
          return res.status(400).json({ error: 'MFA no configurado' });
      }

      const verified = speakeasy.totp.verify({
          secret: user.mfaSecret,
          encoding: 'base32',
          token,
          window: 1
      });

      if (verified) {
          const token = jwt.sign({ userId: user.email }, JWT_SECRET);
          res.json({ 
              success: true, 
              token,
              user: {
                  email: user.email,
                  username: user.username
              }
          });
      } else {
          res.status(401).json({ error: 'Código inválido' });
      }
  } catch (error) {
      console.error('Error en verify-mfa:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
  }
});




const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor listo en http://localhost:${PORT}`);
}).on('error', (err) => {
  console.error('Error crítico:', err.message);
  process.exit(1);
});

// Verificación de conexión a Firebase (opcional pero útil)
testFirebaseConnection();

async function testFirebaseConnection() {
  try {
    const testDocRef = doc(db, '_test', 'connection');
    await setDoc(testDocRef, { test: new Date() });
    await deleteDoc(testDocRef);
    console.log('Conexión a Firebase establecida correctamente');
  } catch (error) {
    console.error('Fallo la conexión con Firebase:', error.message);
  }
}
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userRef = doc(db, 'users', email);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return res.status(404).json({ error: 'No existe una cuenta con este correo' });
    }

    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 600000); // 10 minutos

    const resetRef = doc(db, 'passwordResets', email);
    await setDoc(resetRef, { 
      code, 
      expiresAt: expiresAt.toISOString() // Guardar como string ISO
    });

    await transporter.sendMail({
      from: `Casino Dorado <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Código de recuperación de contraseña',
      html: `<p>Tu código de verificación es: <strong>${code}</strong></p>
             <p>Este código expirará en 10 minutos.</p>`
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error en forgot-password:', error);
    res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  
  console.log('Datos recibidos:', { email, code, newPassword });

  try {
    // Validar nueva contraseña
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, una mayúscula y un número' });
    }

    const resetRef = doc(db, 'passwordResets', email);
    const resetSnap = await getDoc(resetRef);

    if (!resetSnap.exists()) {
      return res.status(400).json({ error: 'Código inválido o expirado' });
    }

    const { code: storedCode, expiresAt } = resetSnap.data();
    const now = new Date();
    const expirationDate = new Date(expiresAt); // Convertir string ISO a Date

    console.log('Comparando:', {
      storedCode,
      receivedCode: code,
      expiresAt: expirationDate.toISOString(),
      now: now.toISOString()
    });

    if (storedCode !== code || now > expirationDate) {
      return res.status(400).json({ error: 'Código inválido o expirado' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const userRef = doc(db, 'users', email);
    
    await updateDoc(userRef, { 
      password: hashedPassword 
    });
    
    await deleteDoc(resetRef);

    res.json({ 
      success: true,
      message: 'Contraseña actualizada correctamente' 
    });
  } catch (error) {
    console.error('Error detallado en reset-password:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      error: 'Error al actualizar la contraseña',
      details: error.message
    });
  }
});