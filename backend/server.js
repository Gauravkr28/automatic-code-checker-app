const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const winston = require('winston'); // Import winston

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '.env') }); // Ensure .env path is correct

const app = express();

// Configure Winston Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        // Add more transports here, e.g., file logging
        // new winston.transports.File({ filename: 'error.log', level: 'error' }),
        // new winston.transports.File({ filename: 'combined.log' }),
    ],
});

// Connect Database
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        logger.info('MongoDB Connected...'); // Using logger
    } catch (err) {
        logger.error('MongoDB connection error:', err.message); // Using logger
        process.exit(1); // Exit process with failure
    }
};

connectDB();

// Init Middleware
app.use(express.json()); // Body parser for JSON
app.use(cors()); // Enable CORS for all origins

// Define Routes
app.use('/api/auth', require('./routes/auth')); // Authentication routes
app.use('/api/analysis', require('./routes/analysis')); // Analysis routes

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
    // Set static folder
    app.use(express.static('client/build'));

    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
    });
}

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => logger.info(`Server started on port ${PORT}`)); // Using logger