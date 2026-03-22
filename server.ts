import express from 'express';
import cookieParser from 'cookie-parser';
import admin from 'firebase-admin';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import path from 'path';

dotenv.config();

const firebaseConfig = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined
};

if (!admin.apps.length) {
  if (!firebaseConfig.projectId || !firebaseConfig.clientEmail || !firebaseConfig.privateKey) {
    console.error('Firebase Admin config missing. Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY in .env');
  } else {
    try {
      admin.initializeApp({
        credential: admin.credential.cert(firebaseConfig as any),
      });
      console.log('Firebase Admin initialized');
    } catch (error) {
      console.error('Firebase Admin Error:', error);
    }
  }
}

if (!admin.apps.length) {
  console.error('Firebase Admin failed to initialize. Auth routes will return errors.');
}

const app = express();
const router = express.Router();

const mailTransport = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 465),
  secure: String(process.env.EMAIL_SECURE).toLowerCase() === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendResetCodeEmail(email: string, code: string) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset Code - Gamer Zone',
    html: `
      <h2>Password Reset</h2>
      <p>You requested to reset your password for your Gamer Zone account.</p>
      <p><strong>Your 4-digit verification code is:</strong></p>
      <p style="font-size: 32px; font-weight: bold; letter-spacing: 0.1em;">${code}</p>
      <p>This code will expire in 15 minutes.</p>
      <p>If you didn't request this, please ignore this email.</p>
    `,
  };
  await mailTransport.sendMail(mailOptions);
}

async function startServer() {
  app.use(express.json());
  app.use(cookieParser());

  // Test Route
  router.get('/health', (req, res) => res.json({ status: 'ok' }));

  const checkFirebaseAdmin = (res: any) => {
    if (!admin.apps.length) {
      console.error('Firebase Admin not initialized when handling request.');
      res.status(500).json({ error: 'Server misconfigured: Firebase Admin not initialized.' });
      return false;
    }
    return true;
  };

  // Password reset code flow
  router.post('/auth/forgot-password', async (req, res) => {
    if (!checkFirebaseAdmin(res)) return;
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    try {
      const user = await admin.auth().getUserByEmail(email);
      if (!user) return res.status(404).json({ error: 'User not found.' });

      const code = `${Math.floor(1000 + Math.random() * 9000)}`;
      const expiresAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + 15 * 60 * 1000));

      await admin.firestore().collection('password_resets').doc(email.toLowerCase()).set({
        email: email.toLowerCase(),
        code,
        expiresAt,
        createdAt: admin.firestore.Timestamp.now(),
      });

      await sendResetCodeEmail(email, code);

      return res.json({ message: 'Reset code sent.' });
    } catch (err: any) {
      console.error('forgot-password error', err);
      return res.status(500).json({ error: err.message || 'Failed to send reset code.' });
    }
  });

  router.post('/auth/verify-code', async (req, res) => {
    if (!checkFirebaseAdmin(res)) return;
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'Email and code are required.' });

    try {
      const doc = await admin.firestore().collection('password_resets').doc(email.toLowerCase()).get();
      if (!doc.exists) return res.status(400).json({ error: 'Invalid code.' });
      const data = doc.data();
      if (!data) return res.status(400).json({ error: 'Invalid code data.' });

      if (data.code !== code) return res.status(400).json({ error: 'Invalid code.' });
      if (data.expiresAt.toMillis() < Date.now()) return res.status(400).json({ error: 'Code expired.' });

      return res.json({ message: 'Code verified.' });
    } catch (err: any) {
      console.error('verify-code error', err);
      return res.status(500).json({ error: err.message || 'Failed to verify code.' });
    }
  });

  router.post('/auth/reset-password', async (req, res) => {
    if (!checkFirebaseAdmin(res)) return;
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword) return res.status(400).json({ error: 'Email, code, and new password are required.' });

    try {
      const docRef = admin.firestore().collection('password_resets').doc(email.toLowerCase());
      const doc = await docRef.get();
      if (!doc.exists) return res.status(400).json({ error: 'Invalid code.' });

      const data = doc.data();
      if (!data || data.code !== code) return res.status(400).json({ error: 'Invalid code.' });
      if (data.expiresAt.toMillis() < Date.now()) return res.status(400).json({ error: 'Code expired.' });

      const user = await admin.auth().getUserByEmail(email);
      await admin.auth().updateUser(user.uid, { password: newPassword });

      await docRef.delete();

      return res.json({ message: 'Password reset successfully.' });
    } catch (err: any) {
      console.error('reset-password error', err);
      return res.status(500).json({ error: err.message || 'Failed to reset password.' });
    }
  });

  // Push Route
  router.post('/send-push', async (req, res) => {
    try {
      const { title, body, targetUserId } = req.body;
      
      if (!admin.apps.length) {
         return res.status(500).json({ error: 'Firebase Admin not initialized' });
      }

      let tokens: string[] = [];

      if (targetUserId) {
        // Send to specific user
        const userDoc = await admin.firestore().collection('users').doc(targetUserId).get();
        if (userDoc.exists) {
          const user = userDoc.data();
          if (user?.fcmTokens && Array.isArray(user.fcmTokens)) {
            tokens = user.fcmTokens;
          }
        }
      } else {
        // Send to all users
        const usersSnap = await admin.firestore().collection('users').get();
        usersSnap.forEach(doc => {
          const user = doc.data();
          if (user.fcmTokens && Array.isArray(user.fcmTokens)) {
            tokens = tokens.concat(user.fcmTokens);
          }
        });
      }

      if (tokens.length === 0) {
        return res.status(404).json({ error: 'No tokens found' });
      }

      const message = {
        notification: { title, body },
        tokens: [...new Set(tokens)].slice(0, 500)
      };

      const response = await admin.messaging().sendEachForMulticast(message);
      res.json({ 
        success: true, 
        count: response.successCount,
        failureCount: response.failureCount 
      });
    } catch (err: any) {
      console.error('Push Error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // Mount API routes
  app.use('/.netlify/functions/api', router);
  app.use('/api', router);

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  if (process.env.NODE_ENV !== 'production' || !process.env.NETLIFY) {
    const PORT = 3000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  }
}

startServer();

export { app };
