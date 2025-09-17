require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Serve uploaded files ---
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Serve frontend static files (for production) ---
const frontendPath = path.join(__dirname, '..', 'frontend', 'build');
const frontendExists = fs.existsSync(frontendPath);

if (frontendExists) {
  console.log('Frontend build found. Serving static files...');
  app.use(express.static(frontendPath));
} else {
  console.log('Frontend build not found. API-only mode.');
  console.log(`Expected frontend path: ${frontendPath}`);
  console.log('To serve frontend, run "npm run build" in frontend directory');
}

// --- Ensure uploads directory exists ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Created uploads directory');
}

// --- Multer Configuration ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    // Sanitize filename and add timestamp
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, Date.now() + '-' + sanitizedName);
  }
});

// Add file filter for security
const fileFilter = (req, file, cb) => {
  // Allow images and videos
  const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|avi|mov|wmv|pdf|doc|docx/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype) || file.mimetype.startsWith('application/');
  
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image, video, and document files are allowed!'));
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// --- Database Connection ---
const connectDB = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error('MONGO_URI environment variable is not set');
    }
    
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully.');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
};

connectDB();

// --- Database Schema ---
const postSchema = new mongoose.Schema({
  title: { 
    type: String, 
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  content: { 
    type: String, 
    required: [true, 'Content is required'],
    trim: true
  },
  category: { 
    type: String, 
    required: [true, 'Category is required'],
    trim: true,
    enum: {
      values: ['job notification', 'admit card', 'result', 'technology', 'lifestyle', 'travel', 'food', 'health', 'business', 'other'],
      message: 'Category must be one of the allowed values'
    }
  },
  mediaUrl: { 
    type: String, 
    required: false 
  },
  mediaType: { 
    type: String, 
    required: false 
  },
  likes: { 
    type: Number, 
    default: 0,
    min: [0, 'Likes cannot be negative']
  },
  views: {
    type: Number,
    default: 0,
    min: [0, 'Views cannot be negative']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Post = mongoose.model('Post', postSchema);

// --- API Security Middleware ---
const apiKeyAuth = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!process.env.API_SECRET_KEY) {
    console.warn('Warning: API_SECRET_KEY not set in environment variables');
    return next(); // Allow if no API key is configured
  }
  
  if (apiKey && apiKey === process.env.API_SECRET_KEY) {
    return next();
  }
  
  if (!apiKey) {
    return next(); // Allow frontend manual edits (no API key provided)
  }
  
  return res.status(401).json({ 
    success: false,
    message: 'Unauthorized: Invalid API Key' 
  });
};

// --- Request logging middleware (optional) ---
const requestLogger = (req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.originalUrl;
  const ip = req.ip || req.connection.remoteAddress;
  
  // Only log API requests in production
  if (req.originalUrl.startsWith('/api/') || process.env.NODE_ENV === 'development') {
    console.log(`${timestamp} - ${method} ${url} - ${ip}`);
  }
  
  next();
};

app.use(requestLogger);

// --- Error handling middleware ---
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err.message);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File size too large. Maximum size is 10MB.'
      });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        message: 'Unexpected file field. Please use "mediaFile" as the field name.'
      });
    }
  }
  
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format'
    });
  }
  
  if (err.name === 'MongoServerError' && err.code === 11000) {
    return res.status(400).json({
      success: false,
      message: 'Duplicate entry found'
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
};

// --- API Routes ---

// Get all posts with pagination and filtering
app.get('/api/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10)); // Max 50 posts per page
    const category = req.query.category;
    const search = req.query.search;
    const sortBy = req.query.sortBy || 'createdAt'; // createdAt, likes, views, title
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    
    // Build query
    let query = { isActive: true }; // Only show active posts
    
    if (category && category !== 'all') {
      query.category = { $regex: new RegExp(category, 'i') };
    }
    
    if (search && search.trim()) {
      const searchRegex = { $regex: search.trim(), $options: 'i' };
      query.$or = [
        { title: searchRegex },
        { content: searchRegex },
        { category: searchRegex }
      ];
    }
    
    const skip = (page - 1) * limit;
    
    // Build sort object
    let sortObj = {};
    sortObj[sortBy] = sortOrder;
    if (sortBy !== 'createdAt') {
      sortObj['createdAt'] = -1; // Secondary sort by creation date
    }
    
    const posts = await Post.find(query)
      .sort(sortObj)
      .skip(skip)
      .limit(limit)
      .select('-__v'); // Exclude version key
      
    const total = await Post.countDocuments(query);
    const totalPages = Math.ceil(total / limit);
    
    res.json({
      success: true,
      data: posts,
      pagination: {
        currentPage: page,
        totalPages,
        totalPosts: total,
        hasMore: page < totalPages,
        limit
      },
      query: {
        search: search || null,
        category: category || 'all',
        sortBy,
        sortOrder: sortOrder === 1 ? 'asc' : 'desc'
      }
    });
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching posts',
      error: error.message 
    });
  }
});

// Get single post and increment view count
app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).select('-__v');
    if (!post || !post.isActive) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }
    
    // Increment view count
    await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
    post.views += 1; // Update the returned post object
    
    res.json({
      success: true,
      data: post
    });
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching post',
      error: error.message
    });
  }
});

// Create new post
app.post('/api/posts', apiKeyAuth, upload.single('mediaFile'), async (req, res) => {
  try {
    const { title, content, category } = req.body;
    
    // Validate required fields
    if (!title?.trim() || !content?.trim() || !category?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Title, content, and category are required'
      });
    }
    
    const newPost = new Post({
      title: title.trim(),
      content: content.trim(),
      category: category.toLowerCase().trim(),
      mediaUrl: req.file ? `/uploads/${req.file.filename}` : null,
      mediaType: req.file ? req.file.mimetype : null,
    });
    
    const savedPost = await newPost.save();
    
    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      data: savedPost
    });
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error creating post', 
      error: error.message 
    });
  }
});

// Update post
app.put('/api/posts/:id', apiKeyAuth, upload.single('mediaFile'), async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ 
        success: false,
        message: 'Post not found' 
      });
    }
    
    const { title, content, category, isActive } = req.body;
    
    // Update fields if provided
    if (title?.trim()) post.title = title.trim();
    if (content?.trim()) post.content = content.trim();
    if (category?.trim()) post.category = category.toLowerCase().trim();
    if (typeof isActive === 'boolean') post.isActive = isActive;
    
    // Handle file upload
    if (req.file) {
      // Delete old file if exists
      if (post.mediaUrl) {
        const oldFilePath = path.join(__dirname, post.mediaUrl);
        try {
          if (fs.existsSync(oldFilePath)) {
            fs.unlinkSync(oldFilePath);
          }
        } catch (fileError) {
          console.warn('Could not delete old file:', fileError.message);
        }
      }
      
      post.mediaUrl = `/uploads/${req.file.filename}`;
      post.mediaType = req.file.mimetype;
    }
    
    post.updatedAt = new Date();
    const updatedPost = await post.save();
    
    res.json({
      success: true,
      message: 'Post updated successfully',
      data: updatedPost
    });
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error updating post', 
      error: error.message 
    });
  }
});

// Soft delete post (set isActive to false)
app.delete('/api/posts/:id', apiKeyAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ 
        success: false,
        message: 'Post not found' 
      });
    }
    
    const forceDelete = req.query.force === 'true';
    
    if (forceDelete) {
      // Hard delete - remove from database and delete file
      if (post.mediaUrl) {
        const filePath = path.join(__dirname, post.mediaUrl);
        try {
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        } catch (fileError) {
          console.warn('Could not delete file:', fileError.message);
        }
      }
      
      await Post.findByIdAndDelete(req.params.id);
      
      res.json({ 
        success: true,
        message: 'Post permanently deleted' 
      });
    } else {
      // Soft delete - just mark as inactive
      post.isActive = false;
      post.updatedAt = new Date();
      await post.save();
      
      res.json({ 
        success: true,
        message: 'Post deactivated successfully' 
      });
    }
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error deleting post', 
      error: error.message 
    });
  }
});

// Like post
app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post || !post.isActive) {
      return res.status(404).json({ 
        success: false,
        message: 'Post not found' 
      });
    }
    
    post.likes += 1;
    const updatedPost = await post.save();
    
    res.json({
      success: true,
      message: 'Post liked successfully',
      data: updatedPost
    });
  } catch (error) {
    console.error('Error liking post:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error liking post', 
      error: error.message 
    });
  }
});

// Unlike post
app.post('/api/posts/:id/unlike', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post || !post.isActive) {
      return res.status(404).json({ 
        success: false,
        message: 'Post not found' 
      });
    }
    
    if (post.likes > 0) {
      post.likes -= 1;
    }
    
    const updatedPost = await post.save();
    
    res.json({
      success: true,
      message: 'Post unliked successfully',
      data: updatedPost
    });
  } catch (error) {
    console.error('Error unliking post:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error unliking post', 
      error: error.message 
    });
  }
});

// Get categories
app.get('/api/categories', (req, res) => {
  const categories = [
    'job notification',
    'admit card', 
    'result',
    'technology', 
    'lifestyle', 
    'travel', 
    'food', 
    'health', 
    'business', 
    'other'
  ];
  
  res.json({
    success: true,
    data: categories
  });
});

// Get statistics
app.get('/api/stats', async (req, res) => {
  try {
    const totalPosts = await Post.countDocuments({ isActive: true });
    const totalLikes = await Post.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: null, total: { $sum: '$likes' } } }
    ]);
    const totalViews = await Post.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: null, total: { $sum: '$views' } } }
    ]);
    
    const categoryStats = await Post.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({
      success: true,
      data: {
        totalPosts,
        totalLikes: totalLikes[0]?.total || 0,
        totalViews: totalViews[0]?.total || 0,
        categories: categoryStats
      }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    // Check uploads directory
    const uploadsExists = fs.existsSync(uploadsDir);
    
    // System info
    const systemInfo = {
      nodeVersion: process.version,
      platform: process.platform,
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
      }
    };
    
    res.json({
      success: true,
      message: 'Server is healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      database: dbStatus,
      uploads: uploadsExists ? 'available' : 'missing',
      frontend: frontendExists ? 'served' : 'not-found',
      system: systemInfo
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Health check failed',
      error: error.message
    });
  }
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    availableEndpoints: [
      'GET /api/posts',
      'GET /api/posts/:id',
      'POST /api/posts',
      'PUT /api/posts/:id',
      'DELETE /api/posts/:id',
      'POST /api/posts/:id/like',
      'POST /api/posts/:id/unlike',
      'GET /api/categories',
      'GET /api/stats',
      'GET /api/health'
    ]
  });
});

// --- Serve Frontend for all other routes (SPA support) ---
if (frontendExists) {
  app.get('*', (req, res) => {
    // Don't serve index.html for API routes or file extensions
    if (req.originalUrl.startsWith('/api/') || req.originalUrl.includes('.')) {
      return res.status(404).json({
        success: false,
        message: 'Resource not found'
      });
    }
    
    res.sendFile(path.join(frontendPath, 'index.html'), (err) => {
      if (err) {
        console.error('Error serving index.html:', err);
        res.status(500).json({
          success: false,
          message: 'Error serving frontend'
        });
      }
    });
  });
} else {
  // If no frontend build exists, show a helpful message
  app.get('*', (req, res) => {
    if (!req.originalUrl.startsWith('/api/')) {
      res.status(404).json({
        success: false,
        message: 'Frontend not available',
        instructions: [
          '1. Navigate to the frontend directory',
          '2. Run "npm install" to install dependencies',
          '3. Run "npm run build" to create a production build',
          '4. Restart this server'
        ]
      });
    }
  });
}

// Apply error handling middleware
app.use(errorHandler);

// --- Graceful Shutdown ---
const gracefulShutdown = async (signal) => {
  console.log(`${signal} received. Shutting down gracefully...`);
  
  try {
    await mongoose.connection.close();
    console.log('Database connection closed.');
    process.exit(0);
  } catch (error) {
    console.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit the process in production
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// --- Start The Server ---
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
  console.log(`📂 Uploads: ${fs.existsSync(uploadsDir) ? 'Ready' : 'Not Found'}`);
  console.log(`🌐 Frontend: ${frontendExists ? 'Served' : 'Build Not Found'}`);
  console.log('='.repeat(50));
  
  if (!frontendExists) {
    console.log('💡 To serve frontend:');
    console.log('   1. cd frontend');
    console.log('   2. npm run build');
    console.log('   3. Restart server');
    console.log('='.repeat(50));
  }
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use`);
    console.log('💡 Try a different port: PORT=3001 npm start');
  } else {
    console.error('❌ Server error:', error);
  }
  process.exit(1);
});

module.exports = app; // Export for testing