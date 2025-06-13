const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../models/Users');
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.simple(),
    transports: [
        new winston.transports.Console(),
    ],
});

// Middleware to protect routes (authenticates JWT) - DEFINED HERE FOR REUSABILITY WITHIN THIS FILE
const authMiddleware = (req, res, next) => {
    // Get token from header
    const token = req.header('Authorization')?.split(' ')[1];

    // Check if no token
    if (!token) {
        // Return JSON error response to prevent SyntaxError on frontend
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; // Attach user info from token to request
        next();
    } catch (err) {
        logger.error('Token verification failed:', err.message);
        // Return JSON error response
        res.status(401).json({ msg: 'Token is not valid' });
    }
};


// @route   POST api/auth/register
// @desc    Register user
// @access  Public
router.post(
    '/register',
    [
        check('username', 'Username is required').not().isEmpty(),
        check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;

        try {
            let user = await User.findOne({ username });

            if (user) {
                return res.status(400).json({ msg: 'User already exists' });
            }

            user = new User({
                username,
                password,
            });

            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id, // Mongoose model uses 'id' as a virtual getter for '_id'
                },
            };

            jwt.sign(
                payload,
                process.env.JWT_SECRET,
                { expiresIn: '1h' }, // Token expires in 1 hour
                (err, token) => {
                    if (err) throw err;
                    res.json({ token, user: { id: user.id, username: user.username } }); // Include user data for frontend
                }
            );
        } catch (err) {
            logger.error('Error in user registration:', err.message);
            res.status(500).json({ msg: 'Server Error' }); // Ensure JSON response
        }
    }
);

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post(
    '/login',
    [
        check('username', 'Username is required').not().isEmpty(),
        check('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;

        try {
            const user = await User.findOne({ username });

            if (!user) {
                return res.status(400).json({ msg: 'Invalid Credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({ msg: 'Invalid Credentials' });
            }

            const payload = {
                user: {
                    id: user.id,
                },
            };

            jwt.sign(
                payload,
                process.env.JWT_SECRET,
                { expiresIn: '1h' },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token, user: { id: user.id, username: user.username } }); // Include user data for frontend
                }
            );
        } catch (err) {
            logger.error('Error in user login:', err.message);
            res.status(500).json({ msg: 'Server Error' }); // Ensure JSON response
        }
    }
);

// @route   GET api/auth/user
// @desc    Get authenticated user (using token)
// @access  Private
// IMPORTANT: authMiddleware IS NOW APPLIED HERE!
router.get('/user', authMiddleware, async (req, res) => {
    try {
        // req.user.id is now guaranteed to exist due to authMiddleware
        const user = await User.findById(req.user.id).select('-password'); // Exclude password
        if (!user) {
            return res.status(404).json({ msg: 'User not found' }); // User might have been deleted
        }
        res.json(user);
    } catch (err) {
        logger.error('Error fetching authenticated user (auth/user route):', err.message);
        res.status(500).json({ msg: 'Server Error fetching user details' }); // Ensure JSON response
    }
});


module.exports = router;
