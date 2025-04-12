
require('dotenv').config();
const express = require('express');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { initializeApp } = require('firebase/app');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const paypal = require('@paypal/checkout-server-sdk');

// Configurar transporter de nodemailer
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
  updateDoc,
  increment
} = require('firebase/firestore');

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

// Configuración de PayPal
let paypalEnvironment;
if (process.env.NODE_ENV === 'production') {
  paypalEnvironment = new paypal.core.LiveEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
  );
} else {
  paypalEnvironment = new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
  );
}
const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment);

const app = express();
app.use(cors());
app.use(express.json());

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Acceso denegado' });
  
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Token inválido' });
  }
};
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
          mfaSecret: tempUser.mfaSecret,
          fichas: 0
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
      from: `El dado de oro <${process.env.EMAIL_USER}>`,
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
// Agrega este nuevo endpoint antes del app.listen
app.get('/api/auth/user', async (req, res) => {
  try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'Acceso no autorizado' });

      const decoded = jwt.verify(token, JWT_SECRET);
      const userRef = doc(db, 'users', decoded.userId);
      const userSnap = await getDoc(userRef);

      if (!userSnap.exists()) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const userData = userSnap.data();
      res.json({
          username: userData.username,
          email: userData.email,
          verified: userData.verified,
          mfaEnabled: userData.mfaEnabled,
          createdAt: userData.createdAt
      });
      
  } catch (error) {
      console.error('Error en /api/auth/user:', error);
      res.status(500).json({ error: 'Error al obtener datos del usuario' });
  }
});
app.put('/api/auth/update-username', async (req, res) => {
  try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'No autorizado' });

      const decoded = jwt.verify(token, JWT_SECRET);
      const { newUsername } = req.body;

      // Validaciones
      if (!validateUsername(newUsername)) {
          return res.status(400).json({ error: 'Nombre de usuario inválido' });
      }

      // Verificar disponibilidad
      const usersRef = collection(db, 'users');
      const q = query(usersRef, where('username', '==', newUsername));
      const snapshot = await getDocs(q);
      
      if (!snapshot.empty) {
          return res.status(400).json({ error: 'Nombre de usuario ya está en uso' });
      }

      // Actualizar en Firestore
      const userRef = doc(db, 'users', decoded.userId);
      await updateDoc(userRef, { 
          username: newUsername 
      });

      res.json({ 
          success: true,
          newUsername 
      });

  } catch (error) {
      console.error('Error actualizando username:', error);
      res.status(500).json({ error: 'Error actualizando usuario' });
  }
});
app.post('/api/payments/create-order', authenticateToken, async (req, res) => {
  try {
    const { paqueteId } = req.body;
    
    // Mapeo de paquetes (misma estructura que tu frontend)
    const paquetes = [
      { id: 0, fichas: 100, precio: 5.00 },
      { id: 1, fichas: 250, precio: 10.00 },
      { id: 2, fichas: 500, precio: 20.00 },
      { id: 3, fichas: 1000, precio: 35.00 },
      { id: 4, fichas: 2500, precio: 75.00 },
      { id: 5, fichas: 5000, precio: 120.00 }
    ];
    
    const paquete = paquetes[paqueteId];
    
    if (!paquete) {
      return res.status(400).json({ error: 'Paquete no válido' });
    }
    
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{
        description: `${paquete.fichas} Fichas para El Dado de Oro`,
        amount: {
          currency_code: 'USD',
          value: paquete.precio.toFixed(2)
        },
        custom_id: `${req.user.userId}|${paqueteId}`
      }]
    });
    
    const order = await paypalClient.execute(request);
    
    // Guardar información de la orden en Firestore
    const orderData = {
      userId: req.user.userId,
      paqueteId: paqueteId,
      fichas: paquete.fichas,
      monto: paquete.precio,
      status: 'CREATED',
      createdAt: new Date().toISOString(),
      paypalOrderId: order.result.id
    };
    
    await setDoc(doc(db, 'orders', order.result.id), orderData);
    
    res.json({
      orderId: order.result.id,
      status: order.result.status
    });
  } catch (error) {
    console.error('Error creando orden:', error);
    res.status(500).json({ error: 'Error al crear la orden' });
  }
});

// Capturar un pago completado
app.post('/api/payments/capture-order', authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.body;
    
    // Verificar que la orden existe en nuestra base de datos
    const orderRef = doc(db, 'orders', orderId);
    const orderSnap = await getDoc(orderRef);
    
    if (!orderSnap.exists()) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }
    
    const orderData = orderSnap.data();
    
    // Verificar que el usuario es el propietario de la orden
    if (orderData.userId !== req.user.userId) {
      return res.status(403).json({ error: 'No autorizado' });
    }
    
    // Capturar la orden en PayPal
    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    request.requestBody({});
    
    const capture = await paypalClient.execute(request);
    
    // Actualizar estado de la orden
    await updateDoc(orderRef, {
      status: 'COMPLETED',
      completedAt: new Date().toISOString(),
      paypalDetails: capture.result
    });
    
    // Añadir fichas al usuario
    const userRef = doc(db, 'users', req.user.userId);
    await updateDoc(userRef, {
      fichas: increment(orderData.fichas)
    });
    
    // Crear registro de transacción
    const transactionId = `txn_${Date.now()}`;
    await setDoc(doc(db, 'transactions', transactionId), {
      userId: req.user.userId,
      orderId: orderId,
      fichas: orderData.fichas,
      tipo: 'COMPRA',
      monto: orderData.monto,
      fecha: new Date().toISOString()
    });
    
    res.json({
      success: true,
      fichasAñadidas: orderData.fichas,
      message: 'Pago completado con éxito'
    });
  } catch (error) {
    console.error('Error capturando orden:', error);
    res.status(500).json({ error: 'Error al procesar el pago' });
  }
});

// Obtener el saldo de fichas del usuario
app.get('/api/user/fichas', authenticateToken, async (req, res) => {
  try {
    const userRef = doc(db, 'users', req.user.userId);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const userData = userSnap.data();
    res.json({ 
      fichas: Number(userData.fichas) || 0 // Asegurar número y valor por defecto
    });
  } catch (error) {
    console.error('Error obteniendo fichas:', error);
    res.json({ fichas: 0 }); // Respuesta segura incluso en errores
  }
});

// Endpoint para obtener historial de transacciones
app.get('/api/user/transactions', authenticateToken, async (req, res) => {
  try {
    const transactionsRef = collection(db, 'transactions');
    const q = query(transactionsRef, where('userId', '==', req.user.userId));
    const querySnapshot = await getDocs(q);
    
    const transactions = [];
    querySnapshot.forEach((doc) => {
      transactions.push({
        id: doc.id,
        ...doc.data()
      });
    });
    
    // Ordenar por fecha, más reciente primero
    transactions.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
    
    res.json({ transactions });
  } catch (error) {
    console.error('Error obteniendo transacciones:', error);
    res.status(500).json({ error: 'Error al obtener historial de transacciones' });
  }
});



// Verificación de conexión a Firebase
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
// En tu server.js (backend)
// Añadir esto al archivo server.js antes del app.listen()

// Endpoint para deducir fichas
app.post('/api/user/deduct-fichas', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }
    
    const userRef = doc(db, 'users', req.user.userId);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const userData = userSnap.data();
    const currentFichas = userData.fichas || 0;
    
    if (currentFichas < amount) {
      return res.status(400).json({ error: 'Fichas insuficientes' });
    }
    
    const newFichas = currentFichas - amount;
    
    await updateDoc(userRef, {
      fichas: newFichas
    });
    
    // Registrar transacción
    const transactionId = `txn_${Date.now()}`;
    await setDoc(doc(db, 'transactions', transactionId), {
      userId: req.user.userId,
      fichas: -amount,
      tipo: 'JUEGO',
      fecha: new Date().toISOString()
    });
    
    res.json({ fichas: newFichas });
  } catch (error) {
    console.error('Error deduciendo fichas:', error);
    res.status(500).json({ error: 'Error al deducir fichas' });
  }
});

// Endpoint para añadir fichas (nuevo)
app.post('/api/user/add-fichas', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }
    
    const userRef = doc(db, 'users', req.user.userId);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const userData = userSnap.data();
    const currentFichas = userData.fichas || 0;
    const newFichas = currentFichas + amount;
    
    await updateDoc(userRef, {
      fichas: newFichas
    });
    
    // Registrar transacción
    const transactionId = `txn_${Date.now()}`;
    await setDoc(doc(db, 'transactions', transactionId), {
      userId: req.user.userId,
      fichas: amount,
      tipo: 'PREMIO',
      fecha: new Date().toISOString()
    });
    
    res.json({ fichas: newFichas });
  } catch (error) {
    console.error('Error añadiendo fichas:', error);
    res.status(500).json({ error: 'Error al añadir fichas' });
  }
});
// Endpoint para canjear productos
app.post('/api/user/canjear-producto', authenticateToken, async (req, res) => {
  try {
    const { productoId, precioFichas } = req.body;
    
    // Validar datos de entrada
    if (!productoId || !precioFichas || precioFichas <= 0) {
      return res.status(400).json({ error: 'Datos de canje inválidos' });
    }

    // Obtener usuario
    const userRef = doc(db, 'users', req.user.userId);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const userData = userSnap.data();
    const fichasActuales = userData.fichas || 0;

    // Verificar fichas suficientes
    if (fichasActuales < precioFichas) {
      return res.status(400).json({ error: 'Fichas insuficientes' });
    }

    // Lista de productos válidos (deberías mover esto a una colección de Firestore)
    const productosValidos = [
      { id: 1, nombre: "Teclado Gaming RGB", precio: 500 },
      { id: 2, nombre: "Auriculares Gaming", precio: 300 },
      { id: 3, nombre: "Mousepad XL", precio: 150 }
    ];

    // Validar producto
    const producto = productosValidos.find(p => p.id === productoId);
    if (!producto || producto.precio !== precioFichas) {
      return res.status(400).json({ error: 'Producto no válido' });
    }

    // Actualizar fichas
    const nuevasFichas = fichasActuales - precioFichas;
    await updateDoc(userRef, {
      fichas: nuevasFichas
    });

    // Registrar transacción
    const transactionId = `canje_${Date.now()}`;
    await setDoc(doc(db, 'transactions', transactionId), {
      userId: req.user.userId,
      tipo: 'CANJE',
      productoId: productoId,
      fichas: -precioFichas,
      detalles: {
        nombreProducto: producto.nombre,
        precio: producto.precio
      },
      fecha: new Date().toISOString()
    });

    // Registrar canje en nueva colección
    const redemptionId = `red_${Date.now()}`;
    await setDoc(doc(db, 'redemptions', redemptionId), {
      userId: req.user.userId,
      productoId: productoId,
      fechaCanje: new Date().toISOString(),
      estado: 'PENDIENTE',
      detallesEnvio: {
        direccion: 'Por definir', // Deberías recolectar esta info
        tracking: null
      }
    });

    res.json({ 
      success: true,
      fichasRestantes: nuevasFichas,
      mensaje: `Canje exitoso: ${producto.nombre}`
    });

  } catch (error) {
    console.error('Error en canje:', error);
    res.status(500).json({ error: 'Error al procesar el canje' });
  }
});
// Agregar en server.js después del endpoint de check-email
app.post('/api/auth/check-username', async (req, res) => {
  const { username } = req.body;
  
  // Verificar en ambas colecciones (users y tempUsers)
  const usersRef = collection(db, 'users');
  const qUsers = query(usersRef, where('username', '==', username));
  const snapshotUsers = await getDocs(qUsers);

  const tempUsersRef = collection(db, 'tempUsers');
  const qTempUsers = query(tempUsersRef, where('username', '==', username));
  const snapshotTempUsers = await getDocs(qTempUsers);

  const isAvailable = snapshotUsers.empty && snapshotTempUsers.empty;
  
  res.json({ available: isAvailable });
});

// Agregar funciones de validación (antes de los endpoints)
function validateUsername(username) {
  return /^[a-zA-Z0-9]{3,20}$/.test(username);
}

function validatePassword(password) {
  return /^(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
}
