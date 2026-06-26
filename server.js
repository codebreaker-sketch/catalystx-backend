// ═══════════════════════════════════════════════════════════════
// CatalystX Backend - Express Server with MongoDB Atlas
// Ready to use - just copy this and follow setup instructions
// ═══════════════════════════════════════════════════════════════

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

// ─────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_change_in_production';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not defined in .env file');
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://yourdomain.com' 
    : ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────────────────────
// DATABASE CONNECTION
// ─────────────────────────────────────────────────────────────
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('✅ Connected to MongoDB Atlas');
    console.log(`📊 Database: ${mongoose.connection.name}`);
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// ─────────────────────────────────────────────────────────────
// USER SCHEMA & MODEL
// ─────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    lowercase: true,
    unique: [true, 'Email already registered'],
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email format'],
    index: true,
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastLogin: Date,
});

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ─────────────────────────────────────────────────────────────
// MIDDLEWARE: VERIFY JWT TOKEN
// ─────────────────────────────────────────────────────────────
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false,
      message: 'No token provided' 
    });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: 'Token expired' 
      });
    }
    return res.status(401).json({ 
      success: false,
      message: 'Invalid token' 
    });
  }
};

// ─────────────────────────────────────────────────────────────
// ROUTES: AUTHENTICATION
// ─────────────────────────────────────────────────────────────

// Register - POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Please provide name, email, and password' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters' 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered' 
      });
    }
    
    // Create new user
    const user = new User({ name, email: email.toLowerCase(), password });
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Set token in localStorage via response
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Registration error:', err);
    
    // Handle mongoose validation errors
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        success: false,
        message: messages[0] 
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration' 
    });
  }
});

// Login - POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Please provide email and password' 
      });
    }
    
    // Find user and select password field
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid email or password' 
      });
    }
    
    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid email or password' 
      });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error during login' 
    });
  }
});

// Get Current User - GET /api/auth/me (Protected)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Get user error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Update User Profile - PUT /api/auth/profile (Protected)
app.put('/api/auth/profile', verifyToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({ 
        success: false,
        message: 'Name is required' 
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      { name },
      { new: true, runValidators: true }
    );
    
    res.json({
      success: true,
      message: 'Profile updated',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Update profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Change Password - POST /api/auth/change-password (Protected)
app.post('/api/auth/change-password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Please provide current and new password' 
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'New password must be at least 6 characters' 
      });
    }
    
    const user = await User.findById(req.userId).select('+password');
    
    const isPasswordValid = await user.comparePassword(currentPassword);
    if (!isPasswordValid) {
      return res.status(400).json({ 
        success: false,
        message: 'Current password is incorrect' 
      });
    }
    
    user.password = newPassword;
    await user.save();
    
    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (err) {
    console.error('❌ Change password error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// ─────────────────────────────────────────────────────────────
// HEALTH CHECK & DEBUG ROUTES
// ─────────────────────────────────────────────────────────────

// Health Check - GET /health
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// Debug - GET /api/users (Admin only - Remove in production)
app.get('/api/users', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: 'Not allowed in production' });
  }
  
  try {
    const users = await User.find();
    res.json({
      success: true,
      count: users.length,
      users: users.map(u => ({
        id: u._id,
        name: u.name,
        email: u.email,
        role: u.role,
        createdAt: u.createdAt,
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching users' });
  }
});

// ─────────────────────────────────────────────────────────────
// 404 & ERROR HANDLING
// ─────────────────────────────────────────────────────────────

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.path}`,
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
  });
});

// ─────────────────────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n' + '═'.repeat(60));
  console.log('🚀 CatalystX Backend Server');
  console.log('═'.repeat(60));
  console.log(`📍 Server: http://localhost:${PORT}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET === 'your_secret_key_change_in_production' ? '⚠️  DEFAULT (change in .env)' : '✅ Custom'}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${mongoose.connection.name || 'connecting...'}`);
  console.log('═'.repeat(60));
  console.log('\n📚 Available Routes:');
  console.log('   POST   /api/auth/register         - Register new user');
  console.log('   POST   /api/auth/login            - Login user');
  console.log('   GET    /api/auth/me               - Get current user (protected)');
  console.log('   PUT    /api/auth/profile          - Update profile (protected)');
  console.log('   POST   /api/auth/change-password  - Change password (protected)');
  console.log('   GET    /health                    - Health check');
  console.log('   GET    /api/users                 - List all users (dev only)');
  console.log('\n💡 Remember:');
  console.log('   - CORS enabled for frontend (http://localhost:5173)');
  console.log('   - MongoDB Atlas connected');
  console.log('   - Remove /api/users route before production\n');
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM signal received: closing HTTP server');
  mongoose.connection.close();
  process.exit(0);
});

module.exports = app;
