const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // Import the new User model

// Removed the in-memory mockUsers array, as users will now be stored in MongoDB.

// @route   POST api/auth/register
// @desc    Register user
// @access  Public
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user already exists in MongoDB
    let user = await User.findOne({ username });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create a new user instance
    user = new User({
      username,
      password, // Password will be hashed before saving
    });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Save user to MongoDB
    await user.save();
    console.log('Registered user:', user.username, 'to MongoDB');

    // Create JWT token
    const payload = {
      user: {
        id: user.id, // Mongoose creates an '_id' field, which we use as 'id'
        username: user.username,
      },
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '7d' }, // Token validity is 7 days
      (err, token) => {
        if (err) throw err;
        res.json({ token, user: { id: user.id, username: user.username } });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error during registration');
  }
});

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user exists in MongoDB
    let user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    // Create JWT token
    const payload = {
      user: {
        id: user.id,
        username: user.username,
      },
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '7d' }, // Token validity is 7 days
      (err, token) => {
        if (err) throw err;
        res.json({ token, user: { id: user.id, username: user.username } });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error during login');
  }
});

module.exports = router;
