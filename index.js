const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();

// ============ DOMAIN RESTRICTION MIDDLEWARE ============
const allowedDomains = [
  'zulqarnain-hanafi-barelvi.lovestoblog.com',
  'localhost',
  '127.0.0.1'
];

const domainRestriction = (req, res, next) => {
  const origin = req.headers.origin || req.headers.referer || '';
  const isAllowed = allowedDomains.some(domain => origin.includes(domain));
  
  // Admin APIs ke liye strict check
  if (req.path.startsWith('/api/admin/')) {
    if (!isAllowed && process.env.NODE_ENV !== 'development') {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. This backend only works with zulqarnain-hanafi-barelvi.lovestoblog.com' 
      });
    }
  }
  next();
};

app.use(domainRestriction);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedDomains.some(domain => origin.includes(domain))) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json());

// ============ FIREBASE ADMIN INIT ============
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
const JWT_SECRET = process.env.JWT_SECRET || 'zulqarnain-secret-key-2025';

// ============ VERIFY TOKEN MIDDLEWARE ============
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

// ============ 1. ADMIN LOGIN ============
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

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

    const token = jwt.sign(
      { 
        adminId: adminSnapshot.docs[0].id, 
        email: adminData.email,
        role: adminData.role || 'admin'
      },
      JWT_SECRET,
      { expiresIn: '30d' }
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

// ============ 2. CREATE FIRST ADMIN (One-time) ============
app.post('/api/admin/setup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
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

// ============ 3. VERIFY TOKEN ============
app.post('/api/admin/verify', verifyToken, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

// ============ 4. GET ALL ARTICLES (Admin Panel) ============
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

// ============ 5. GET SINGLE ARTICLE by ID ============
app.get('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await db.collection('articles').doc(id).get();
    
    if (!doc.exists) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }
    
    res.json({ success: true, article: { id: doc.id, ...doc.data() } });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 6. CREATE NEW ARTICLE ============
app.post('/api/admin/articles', verifyToken, async (req, res) => {
  try {
    const { title, slug, category, content, featuredImage, images, excerpt } = req.body;
    
    // Validation
    if (!title || !slug || !category || !content) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    // Check if slug already exists
    const existingSlug = await db.collection('articles')
      .where('slug', '==', slug)
      .get();
    
    if (!existingSlug.empty) {
      return res.status(400).json({ success: false, message: 'Slug already exists' });
    }
    
    const articleData = {
      title,
      slug,
      category,
      content, // HTML content with images, bold text, etc.
      featuredImage: featuredImage || '',
      images: images || [],
      excerpt: excerpt || title.substring(0, 150),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'published'
    };
    
    const docRef = await db.collection('articles').add(articleData);
    
    res.json({ 
      success: true, 
      message: 'Article created successfully',
      articleId: docRef.id 
    });
  } catch (error) {
    console.error('Create article error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 7. UPDATE ARTICLE ============
app.put('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, slug, category, content, featuredImage, images, excerpt } = req.body;
    
    // Check if article exists
    const articleRef = db.collection('articles').doc(id);
    const articleDoc = await articleRef.get();
    
    if (!articleDoc.exists) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }
    
    // Check slug uniqueness (if changing slug)
    if (slug && slug !== articleDoc.data().slug) {
      const existingSlug = await db.collection('articles')
        .where('slug', '==', slug)
        .get();
      
      if (!existingSlug.empty) {
        return res.status(400).json({ success: false, message: 'Slug already exists' });
      }
    }
    
    const updateData = {
      title: title || articleDoc.data().title,
      slug: slug || articleDoc.data().slug,
      category: category || articleDoc.data().category,
      content: content || articleDoc.data().content,
      featuredImage: featuredImage !== undefined ? featuredImage : articleDoc.data().featuredImage,
      images: images !== undefined ? images : articleDoc.data().images,
      excerpt: excerpt || title?.substring(0, 150) || articleDoc.data().excerpt,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    
    await articleRef.update(updateData);
    
    res.json({ success: true, message: 'Article updated successfully' });
  } catch (error) {
    console.error('Update article error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 8. DELETE ARTICLE ============
app.delete('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const articleRef = db.collection('articles').doc(id);
    const articleDoc = await articleRef.get();
    
    if (!articleDoc.exists) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }
    
    await articleRef.delete();
    res.json({ success: true, message: 'Article deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 9. GET ALL CATEGORIES ============
app.get('/api/categories', async (req, res) => {
  try {
    const categoriesSnapshot = await db.collection('categories').get();
    const categories = [];
    categoriesSnapshot.forEach(doc => {
      categories.push({ id: doc.id, ...doc.data() });
    });
    res.json({ success: true, categories });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 10. CREATE CATEGORY ============
app.post('/api/admin/categories', verifyToken, async (req, res) => {
  try {
    const { name, slug, description } = req.body;
    
    if (!name || !slug) {
      return res.status(400).json({ success: false, message: 'Name and slug required' });
    }
    
    const existing = await db.collection('categories')
      .where('slug', '==', slug)
      .get();
    
    if (!existing.empty) {
      return res.status(400).json({ success: false, message: 'Category slug exists' });
    }
    
    const categoryData = {
      name,
      slug,
      description: description || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    
    const docRef = await db.collection('categories').add(categoryData);
    res.json({ success: true, message: 'Category created', categoryId: docRef.id });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 11. UPDATE CATEGORY ============
app.put('/api/admin/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, slug, description } = req.body;
    
    await db.collection('categories').doc(id).update({
      name: name || '',
      slug: slug || '',
      description: description || '',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({ success: true, message: 'Category updated' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 12. DELETE CATEGORY ============
app.delete('/api/admin/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('categories').doc(id).delete();
    res.json({ success: true, message: 'Category deleted' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 13. GET PUBLIC ARTICLES (Frontend) ============
app.get('/api/public/articles', async (req, res) => {
  try {
    const { limit = 20, category } = req.query;
    
    let query = db.collection('articles')
      .where('status', '==', 'published')
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit));
    
    if (category) {
      query = query.where('category', '==', category);
    }
    
    const articlesSnapshot = await query.get();
    const articles = [];
    articlesSnapshot.forEach(doc => {
      articles.push({ id: doc.id, ...doc.data() });
    });
    
    res.json({ success: true, articles });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 14. GET SINGLE PUBLIC ARTICLE by SLUG ============
app.get('/api/public/article/:slug', async (req, res) => {
  try {
    const { slug } = req.params;
    const articlesSnapshot = await db.collection('articles')
      .where('slug', '==', slug)
      .where('status', '==', 'published')
      .limit(1)
      .get();
    
    if (articlesSnapshot.empty) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }
    
    const doc = articlesSnapshot.docs[0];
    res.json({ success: true, article: { id: doc.id, ...doc.data() } });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 15. HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    domain: 'zulqarnain-hanafi-barelvi.lovestoblog.com',
    timestamp: new Date().toISOString() 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🔒 Domain restricted to: ${allowedDomains.join(', ')}`);
});

module.exports = app;
