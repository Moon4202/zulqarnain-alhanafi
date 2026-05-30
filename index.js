const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();

// ============ Increased body limit for large articles with images ============
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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

// ============ MIDDLEWARE: Verify JWT Token ============
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

// ============ 1. ADMIN SETUP (One-time use) ============
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

// ============ 2. ADMIN LOGIN ============
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

// ============ 3. VERIFY TOKEN ============
app.post('/api/admin/verify', verifyToken, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

// ============ 4. CREATE NEW ARTICLE ============
app.post('/api/admin/articles', verifyToken, async (req, res) => {
  try {
    const {
      title,
      slug,
      content,
      category,
      featuredImage,
      images,
      metaDescription,
      tags
    } = req.body;

    if (!title || !slug || !content) {
      return res.status(400).json({ success: false, message: 'Title, slug and content are required' });
    }

    const existingSlug = await db.collection('articles')
      .where('slug', '==', slug)
      .get();
    
    if (!existingSlug.empty) {
      return res.status(400).json({ success: false, message: 'Slug already exists' });
    }

    const articleData = {
      title,
      slug,
      content,
      category: category || 'Uncategorized',
      featuredImage: featuredImage || '',
      images: images || [],
      metaDescription: metaDescription || title.substring(0, 160),
      tags: tags || [],
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      views: 0
    };

    const docRef = await db.collection('articles').add(articleData);
    
    res.json({
      success: true,
      message: 'Article created successfully',
      articleId: docRef.id,
      slug: slug
    });
  } catch (error) {
    console.error('Create article error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 5. UPDATE ARTICLE ============
app.put('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      slug,
      content,
      category,
      featuredImage,
      images,
      metaDescription,
      tags
    } = req.body;

    if (!title || !slug || !content) {
      return res.status(400).json({ success: false, message: 'Title, slug and content are required' });
    }

    const existingSlug = await db.collection('articles')
      .where('slug', '==', slug)
      .get();
    
    if (!existingSlug.empty) {
      for (const doc of existingSlug.docs) {
        if (doc.id !== id) {
          return res.status(400).json({ success: false, message: 'Slug already exists for another article' });
        }
      }
    }

    const updateData = {
      title,
      slug,
      content,
      category: category || 'Uncategorized',
      featuredImage: featuredImage || '',
      images: images || [],
      metaDescription: metaDescription || title.substring(0, 160),
      tags: tags || [],
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await db.collection('articles').doc(id).update(updateData);
    
    res.json({
      success: true,
      message: 'Article updated successfully'
    });
  } catch (error) {
    console.error('Update article error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 6. DELETE ARTICLE ============
app.delete('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('articles').doc(id).delete();
    res.json({ success: true, message: 'Article deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 7. GET SINGLE ARTICLE BY SLUG (Public) ============
app.get('/api/articles/slug/:slug', async (req, res) => {
  try {
    const { slug } = req.params;
    
    const articleSnapshot = await db.collection('articles')
      .where('slug', '==', slug)
      .limit(1)
      .get();

    if (articleSnapshot.empty) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }

    const doc = articleSnapshot.docs[0];
    const article = { id: doc.id, ...doc.data() };
    
    await db.collection('articles').doc(doc.id).update({
      views: admin.firestore.FieldValue.increment(1)
    });
    
    res.json({ success: true, article });
  } catch (error) {
    console.error('Get article error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 8. GET ALL ARTICLES (Public - with pagination & category filter) ============
app.get('/api/articles', async (req, res) => {
  try {
    const { limit = 10, page = 1, category } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = db.collection('articles').orderBy('createdAt', 'desc');
    
    // Fix: Properly handle category filter with Unicode/Urdu text
    if (category && category !== 'all' && category !== 'undefined' && category !== 'null') {
      // Decode URI component if needed and compare as string
      const decodedCategory = decodeURIComponent(category);
      query = query.where('category', '==', decodedCategory);
    }
    
    const articlesSnapshot = await query.get();
    
    const allArticles = [];
    articlesSnapshot.forEach(doc => {
      allArticles.push({ id: doc.id, ...doc.data() });
    });
    
    const paginatedArticles = allArticles.slice(offset, offset + parseInt(limit));
    const total = allArticles.length;
    
    res.json({
      success: true,
      articles: paginatedArticles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalArticles: total,
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Get articles error:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// ============ 9. GET ALL ARTICLES FOR ADMIN ============
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
    console.error('Admin get articles error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 10. GET SINGLE ARTICLE BY ID (Admin) ============
app.get('/api/admin/articles/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await db.collection('articles').doc(id).get();
    
    if (!doc.exists) {
      return res.status(404).json({ success: false, message: 'Article not found' });
    }
    
    res.json({ success: true, article: { id: doc.id, ...doc.data() } });
  } catch (error) {
    console.error('Get article by id error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 11. CATEGORIES - GET ALL ============
app.get('/api/admin/categories/list', verifyToken, async (req, res) => {
  try {
    const categoriesSnapshot = await db.collection('categories').get();
    const categories = [];
    categoriesSnapshot.forEach(doc => {
      categories.push({ id: doc.id, ...doc.data() });
    });
    res.json({ success: true, categories });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 12. CATEGORIES - CREATE ============
app.post('/api/admin/categories', verifyToken, async (req, res) => {
  try {
    const { name, slug, description } = req.body;
    if (!name) {
      return res.status(400).json({ success: false, message: 'Category name required' });
    }
    const categoryData = {
      name,
      slug: slug || name.toLowerCase().replace(/ /g, '-'),
      description: description || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    const docRef = await db.collection('categories').add(categoryData);
    res.json({ success: true, message: 'Category created', id: docRef.id });
  } catch (error) {
    console.error('Create category error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 13. CATEGORIES - DELETE ============
app.delete('/api/admin/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('categories').doc(id).delete();
    res.json({ success: true, message: 'Category deleted' });
  } catch (error) {
    console.error('Delete category error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 14. PUBLIC CATEGORIES (for index page) ============
app.get('/api/categories/all', async (req, res) => {
  try {
    const categoriesSnapshot = await db.collection('categories').get();
    const categories = [];
    categoriesSnapshot.forEach(doc => {
      categories.push({ id: doc.id, ...doc.data() });
    });
    res.json({ success: true, categories });
  } catch (error) {
    console.error('Get public categories error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 15. VERSES (Quran & Hadith) - GET ALL ============
app.get('/api/admin/verses', verifyToken, async (req, res) => {
  try {
    const versesSnapshot = await db.collection('verses').orderBy('createdAt', 'desc').get();
    const verses = [];
    versesSnapshot.forEach(doc => {
      verses.push({ id: doc.id, ...doc.data() });
    });
    res.json({ success: true, verses });
  } catch (error) {
    console.error('Get verses error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 16. VERSES - CREATE ============
app.post('/api/admin/verses', verifyToken, async (req, res) => {
  try {
    const { content, type } = req.body;
    if (!content || !type) {
      return res.status(400).json({ success: false, message: 'Content and type required' });
    }
    const verseData = {
      content,
      type,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    const docRef = await db.collection('verses').add(verseData);
    res.json({ success: true, message: 'Verse added', id: docRef.id });
  } catch (error) {
    console.error('Create verse error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 17. VERSES - DELETE ============
app.delete('/api/admin/verses/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('verses').doc(id).delete();
    res.json({ success: true, message: 'Verse deleted' });
  } catch (error) {
    console.error('Delete verse error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 18. PUBLIC VERSES (Random for index page) ============
app.get('/api/verses/random', async (req, res) => {
  try {
    const { type } = req.query;
    let query = db.collection('verses');
    if (type && (type === 'quran' || type === 'hadith')) {
      query = query.where('type', '==', type);
    }
    const snapshot = await query.get();
    const verses = [];
    snapshot.forEach(doc => {
      verses.push({ id: doc.id, ...doc.data() });
    });
    if (verses.length === 0) {
      return res.json({ success: true, verse: null });
    }
    const randomVerse = verses[Math.floor(Math.random() * verses.length)];
    res.json({ success: true, verse: randomVerse });
  } catch (error) {
    console.error('Random verse error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 19. GET FEATURED ARTICLES (Most viewed) ============
app.get('/api/articles/featured', async (req, res) => {
  try {
    const articlesSnapshot = await db.collection('articles')
      .orderBy('views', 'desc')
      .limit(6)
      .get();
    
    const articles = [];
    articlesSnapshot.forEach(doc => {
      articles.push({ id: doc.id, ...doc.data() });
    });
    
    res.json({ success: true, articles });
  } catch (error) {
    console.error('Get featured error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 20. SEARCH ARTICLES ============
app.get('/api/articles/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q) {
      return res.json({ success: true, articles: [] });
    }
    
    const articlesSnapshot = await db.collection('articles')
      .orderBy('createdAt', 'desc')
      .get();
    
    const allArticles = [];
    articlesSnapshot.forEach(doc => {
      const data = doc.data();
      allArticles.push({ id: doc.id, ...data });
    });
    
    const searchTerm = q.toLowerCase();
    const filteredArticles = allArticles.filter(article => 
      article.title.toLowerCase().includes(searchTerm) ||
      (article.content && article.content.toLowerCase().includes(searchTerm)) ||
      (article.tags && article.tags.some(tag => tag.toLowerCase().includes(searchTerm)))
    );
    
    res.json({ success: true, articles: filteredArticles });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============ 21. HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`📝 Available endpoints:`);
  console.log(`   POST   /api/admin/setup`);
  console.log(`   POST   /api/admin/login`);
  console.log(`   GET    /api/articles`);
  console.log(`   GET    /api/articles/slug/:slug`);
  console.log(`   GET    /api/articles/search`);
  console.log(`   GET    /api/articles/featured`);
  console.log(`   GET    /api/verses/random`);
  console.log(`   GET    /api/categories/all`);
  console.log(`   POST   /api/admin/articles (Admin)`);
  console.log(`   PUT    /api/admin/articles/:id (Admin)`);
  console.log(`   DELETE /api/admin/articles/:id (Admin)`);
  console.log(`   GET    /api/admin/categories/list (Admin)`);
  console.log(`   POST   /api/admin/categories (Admin)`);
  console.log(`   DELETE /api/admin/categories/:id (Admin)`);
  console.log(`   GET    /api/admin/verses (Admin)`);
  console.log(`   POST   /api/admin/verses (Admin)`);
  console.log(`   DELETE /api/admin/verses/:id (Admin)`);
});

module.exports = app;
