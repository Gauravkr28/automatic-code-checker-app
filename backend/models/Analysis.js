const mongoose = require('mongoose');

// Define a sub-schema for individual issues
const IssueSchema = new mongoose.Schema({
    id: { type: String, required: true },
    type: { type: String, required: true }, // e.g., 'error', 'warning', 'info'
    message: { type: String, required: true },
    line: { type: Number, required: false, default: 0 },
}, { _id: false });

// Define a sub-schema for individual suggestions
const SuggestionSchema = new mongoose.Schema({
    id: { type: String, required: true },
    message: { type: String, required: true },
}, { _id: false });

// Define the main schema for code analysis results
const AnalysisSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
    },
    originalCode: {
        type: String,
        required: true,
    },
    issues: [IssueSchema],
    suggestions: [SuggestionSchema],
    timestamp: {
        type: Date,
        default: Date.now,
    },
});

module.exports = mongoose.model('Analysis', AnalysisSchema);
