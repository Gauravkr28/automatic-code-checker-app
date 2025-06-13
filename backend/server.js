    const express = require('express');
    const mongoose = require('mongoose');
    const dotenv = require('dotenv');
    const cors = require('cors'); // Already imported
    const path = require('path');
    const winston = require('winston');

    dotenv.config({ path: path.resolve(__dirname, '.env') });

    const app = express();

    const logger = winston.createLogger({
        level: 'info',
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
        ),
        transports: [
            new winston.transports.Console(),
        ],
    });

    const connectDB = async () => {
        try {
            await mongoose.connect(process.env.MONGO_URI);
            logger.info('MongoDB Connected...');
        } catch (err) {
            logger.error('MongoDB connection error:', err.message);
            process.exit(1);
        }
    };

    connectDB();

    app.use(express.json());

    // --- IMPORTANT: Configure CORS explicitly for your Vercel frontend URL ---
    const allowedOrigins = [
        'http://localhost:3000', // For local frontend development
        'https://automatic-code-checker-app.vercel.app', // Your deployed Vercel frontend URL
        // Add any other specific frontend URLs if you have them
    ];

    app.use(cors({
        origin: function (origin, callback) {
            // Allow requests with no origin (like mobile apps or curl requests)
            if (!origin) return callback(null, true);
            if (allowedOrigins.indexOf(origin) === -1) {
                const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
                return callback(new Error(msg), false);
            }
            return callback(null, true);
        },
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Explicitly allowed methods
        credentials: true, // Allow cookies, authorization headers, etc.
    }));
    // -------------------------------------------------------------------------

    // Define Routes
    app.use('/api/auth', require('./routes/auth'));
    app.use('/api/analysis', require('./routes/analysis'));

    if (process.env.NODE_ENV === 'production') {
        app.use(express.static('client/build'));
        app.get('*', (req, res) => {
            res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
        });
    }

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => logger.info(`Server started on port ${PORT}`));
    