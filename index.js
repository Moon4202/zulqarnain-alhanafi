const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
    })
  });
}

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// ============ ADMIN LOGIN ============
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    // Get admin user from Firestore
    const adminSnapshot = await db.collection('admins')
      .where('email', '==', email)
      .limit(1)
      .get();

    if (adminSnapshot.empty) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const adminData = adminSnapshot.docs[0].data();
    const isValidPassword = await bcrypt.compare(password, adminData.passwordHash);

    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        adminId: adminSnapshot.docs[0].id, 
        email: adminData.email,
        role: adminData.role || 'admin'
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      admin: {
        email: adminData.email,
        name: adminData.name || 'Admin'
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ VERIFY TOKEN (Middleware) ============
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// ============ CREATE FIRST ADMIN (One-time use - remove after first admin created) ============
app.post('/api/admin/setup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Check if any admin exists
    const adminsCount = await db.collection('admins').get();
    if (!adminsCount.empty) {
      return res.status(403).json({ success: false, message: 'Setup already completed' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    await db.collection('admins').add({
      email,
      passwordHash,
      name: name || 'Super Admin',
      role: 'super-admin',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, message: 'Admin created successfully' });
  } catch (error) {
    console.error('Setup error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ VERIFY TOKEN ROUTE ============
app.post('/api/admin/verify', verifyToken, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ OPTIONAL: Get all articles (admin panel ke liye) ============
app.get('/api/admin/articles', verifyToken, async (req, res) => {
  try {
    const articlesSnapshot = await db.collection('articles')
      .orderBy('createdAt', 'desc')
      .get();
    
    const articles = [];
    articlesSnapshot.forEach(doc => {
      articles.push({ id: doc.id, ...doc.data() });
    });
    
    res.json({ success: true, articles });
  } catch (error) {
    console.error('Error fetching articles:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ DELETE article (admin only) ============
app.delete('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('articles').doc(id).delete();
    res.json({ success: true, message: 'Article deleted' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Export for Vercel
module.exports = app;
