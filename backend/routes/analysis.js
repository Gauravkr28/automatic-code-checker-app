const express = require('express');
const router = express.Router();
const Analysis = require('../models/Analysis'); // Ensure this imports the updated model
const PDFDocument = require('pdfkit');
const { exec } = require('child_process');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const jwt = require('jsonwebtoken'); // Import jsonwebtoken

// Middleware to protect routes (authenticates JWT)
const authMiddleware = (req, res, next) => {
    // Get token from header
    const token = req.header('Authorization')?.split(' ')[1]; // Expects "Bearer TOKEN"

    // Check if no token
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; // Attach user info from token to request
        next();
    } catch (err) {
        console.error('Token verification failed:', err.message);
        res.status(401).json({ msg: 'Token is not valid' });
    }
};


/**
 * Runs static analysis on the provided JavaScript code using ESLint.
 * This is a simplified example. In a production system, consider:
 * - More robust error handling.
 * - **CRITICALLY: Better sandboxing (e.g., dedicated isolated environments or Docker containers)**
 * for executing child processes with user-provided code, to prevent malicious code execution.
 * - Support for multiple languages by calling different linters/SAST tools.
 * @param {string} codeContent The JavaScript code string to analyze.
 * @returns {Promise<{issues: Array, suggestions: Array}>} An object containing found issues and suggestions.
 */
async function runStaticAnalysis(codeContent) {
    const issues = [];
    const suggestions = [];
    let tempDir; // Declare outside try block for finally access

    try {
        tempDir = path.join(os.tmpdir(), `code-checker-${Date.now()}`);
        await fs.mkdir(tempDir, { recursive: true });
        const tempFilePath = path.join(tempDir, 'user_code.js');
        await fs.writeFile(tempFilePath, codeContent);

        // Path to the ESLint executable within node_modules
        const eslintCliPath = path.join(__dirname, '../node_modules/.bin/eslint');
        // Path to the .eslintrc.json file in the backend directory
        const eslintConfigPath = path.join(__dirname, '../.eslintrc.json');

        // Command to run ESLint. --format json outputs results in JSON.
        // --no-error-on-unmatched-pattern helps when parsing single files
        const command = `${eslintCliPath} --format json --config "${eslintConfigPath}" "${tempFilePath}" --no-error-on-unmatched-pattern`;

        let stdout = '';
        let stderr = '';
        try {
            const { stdout: execStdout, stderr: execStderr } = await new Promise((resolve, reject) => {
                // Added timeout to prevent hanging processes
                exec(command, { timeout: 15000 }, (error, stdout, stderr) => {
                    // ESLint exits with error code if linting issues are found,
                    // but stdout still contains the JSON report. So, we resolve even if 'error' exists.
                    resolve({ stdout, stderr });
                });
            });
            stdout = execStdout;
            stderr = execStderr;
        } catch (execError) {
            // This catch handles issues like command not found, timeout, etc.
            console.error('ESLint CLI execution error:', execError);
            issues.push({
                id: 'eslint-cli-error',
                type: 'error',
                message: `ESLint execution failed: ${execError.message}. Ensure ESLint is installed and configured correctly on the server.`,
                line: 0,
            });
            return { issues, suggestions };
        }

        if (stderr) {
            console.warn('ESLint stderr output (non-JSON):', stderr); // Log stderr separately
        }

        let parsedEslintReport;
        try {
            // Trim whitespace and newlines from stdout before parsing to ensure valid JSON
            parsedEslintReport = JSON.parse(stdout.trim());
        } catch (parseError) {
            console.error('Failed to parse ESLint JSON output (raw output below):', stdout, parseError);
            issues.push({
                id: 'analysis-parse-error',
                type: 'error',
                message: 'Backend failed to parse ESLint results. This might be due to severe syntax errors in your submitted code or an unexpected ESLint output format.',
                line: 0,
            });
            // Attempt to extract specific parsing error message from ESLint's stdout if available
            const eslintSyntaxErrorMatch = stdout.match(/Parsing error: (.*) \(\d+:\d+\)/);
            if (eslintSyntaxErrorMatch && eslintSyntaxErrorMatch[1]) {
                issues.push({
                    id: 'code-syntax-error',
                    type: 'error',
                    message: `Your code has a syntax error: ${eslintSyntaxErrorMatch[1]}. Please fix it.`,
                    line: 0, // Cannot reliably get line number from this generic match
                });
            }
            return { issues, suggestions };
        }

        // ESLint's JSON output is typically an array of file result objects.
        // Each file result object has a 'messages' array containing the actual linting issues.
        if (Array.isArray(parsedEslintReport) && parsedEslintReport.length > 0 &&
            parsedEslintReport[0] && typeof parsedEslintReport[0] === 'object' && // Ensure it's an object
            Array.isArray(parsedEslintReport[0].messages)) {
            parsedEslintReport[0].messages.forEach(msg => {
                const type = msg.severity === 2 ? 'error' : msg.severity === 1 ? 'warning' : 'info';
                issues.push({
                    // Ensure all fields expected by Mongoose schema are present and correct types
                    id: String(`eslint-${msg.ruleId || 'unknown'}-${msg.line || 0}-${msg.column || 0}`), // Explicitly cast to String
                    type: String(type), // Explicitly cast to String
                    message: String(msg.message), // Ensure message is explicitly a string
                    line: Number(msg.line) || 0, // Ensure line is explicitly a number, default to 0
                });
            });
        } else {
            console.warn('ESLint returned valid JSON but with an unexpected structure for messages:', parsedEslintReport);
            issues.push({
                id: 'eslint-output-structure-invalid',
                type: 'warning',
                message: 'ESLint analysis returned an unexpected structure. Results might be incomplete.',
                line: 0,
            });
        }

        // --- Start of Generic Code Quality Suggestions (Independent of length) ---
        suggestions.push({ id: 'sugg-modularity', message: 'Consider breaking down large functions or files into smaller, more focused modules for better readability and maintainability.' });
        suggestions.push({ id: 'sugg-naming-conventions', message: 'Apply consistent naming conventions (e.g., camelCase for variables, PascalCase for components) throughout your code for clarity.' });
        suggestions.push({ id: 'sugg-comments', message: 'Add meaningful comments to explain complex logic, choices, or edge cases, but avoid commenting on obvious code.' });
        suggestions.push({ id: 'sugg-dead-code', message: 'Regularly review and remove dead or unreachable code to reduce complexity and bundle size.' });
        suggestions.push({ id: 'sugg-error-handling-robust', message: 'Implement robust error handling for all asynchronous operations and potential failure points to ensure graceful degradation.' });


        // Conditional suggestions (still useful)
        if (codeContent.includes('// TODO')) {
            suggestions.push({ id: 'sugg-todo-comment', message: 'Found a `// TODO` comment. Address pending tasks or remove if no longer relevant.' });
        }
        // These try-catch suggestions are now more specific and less generic.
        if (!codeContent.includes('try') && codeContent.includes('catch') && (codeContent.includes('fetch') || codeContent.includes('axios') || codeContent.includes('async'))) {
            suggestions.push({ id: 'sugg-async-error-handling', message: 'For asynchronous operations (like fetch/axios or async functions), ensure proper error handling with `try...catch` blocks to prevent unhandled promise rejections.' });
        } else if (!codeContent.includes('try') && codeContent.includes('catch') && (codeContent.includes('read') || codeContent.includes('write') || codeContent.includes('open'))) {
            suggestions.push({ id: 'sugg-io-error-handling', message: 'Consider using `try...catch` for error handling in I/O operations (like file reads/writes) to handle potential failures gracefully.' });
        } else if (!codeContent.includes('try') && codeContent.includes('catch')) { // General fallback if no specific async/io indicators
            suggestions.push({ id: 'sugg-general-error-handling', message: 'Consider using `try...catch` for error handling in potentially risky or complex operations to prevent application crashes and provide graceful fallbacks.' });
        }
        // --- End of Generic Code Quality Suggestions ---


    } catch (err) {
        console.error('An unexpected error occurred in runStaticAnalysis (outer catch):', err);
        issues.push({
            id: 'internal-analysis-failure',
            type: 'error',
            message: `An unexpected internal error prevented full code analysis: ${err.message}. Please report this.`,
            line: 0,
        });
    } finally {
        // Ensure temporary directory is cleaned up
        if (tempDir) {
            await fs.rm(tempDir, { recursive: true, force: true }).catch(cleanupErr => {
                console.error('Failed to clean up temporary directory:', cleanupErr);
            });
        }
    }

    return { issues, suggestions };
}

// @route   POST api/analysis
// @desc    Analyze code and save result
// @access  Private (requires authMiddleware)
router.post('/', authMiddleware, async (req, res) => {
    const { code } = req.body;
    const userId = req.user.id; // Get user ID from authenticated token

    if (!code) {
        return res.status(400).json({ msg: 'Code is required for analysis' });
    }

    try {
        const { issues, suggestions } = await runStaticAnalysis(code);

        const newAnalysis = new Analysis({
            userId,
            originalCode: code,
            issues: issues, // This should now be a clean array of IssueSchema objects
            suggestions: suggestions, // This should be a clean array of SuggestionSchema objects
        });

        await newAnalysis.save();

        res.json(newAnalysis);
    } catch (err) {
        console.error('Error saving analysis to DB or in analysis route:', err); // Log the full error object for server-side debugging

        let clientErrorMessage = 'An internal server error occurred during analysis.';

        // Check for specific Mongoose validation errors
        if (err.name === 'ValidationError') {
            // Accessing errors directly from the ValidationError object
            const errorPaths = Object.keys(err.errors);
            if (errorPaths.length > 0) {
                const firstErrorPath = errorPaths[0];
                const firstErrorMessage = err.errors[firstErrorPath].message;
                clientErrorMessage = `Database Validation Error: ${firstErrorPath} - ${firstErrorMessage}`;
            } else {
                clientErrorMessage = `Database Validation Error: ${err.message}`;
            }
        } else if (err.message) {
            clientErrorMessage = `Server Error: ${err.message}`;
        }

        res.status(500).json({ msg: clientErrorMessage }); // Always send valid JSON
    }
});

// @route   GET api/analysis/history
// @desc    Get all analysis history for a user
// @access  Private (requires authMiddleware)
router.get('/history', authMiddleware, async (req, res) => {
    try {
        const analysisHistory = await Analysis.find({ userId: req.user.id }).sort({ timestamp: -1 }); // Filter by authenticated user ID
        res.json(analysisHistory);
    } catch (err) {
        console.error('Error fetching analysis history:', err);
        res.status(500).json({ msg: `Failed to fetch history: ${err.message}` });
    }
});

// @route   GET api/analysis/report/:id
// @desc    Generate PDF report for a specific analysis
// @access  Private (requires authMiddleware)
router.get('/report/:id', authMiddleware, async (req, res) => {
    try {
        const analysis = await Analysis.findById(req.params.id);

        if (!analysis || analysis.userId !== req.user.id) { // Ensure user owns the analysis
            return res.status(404).json({ msg: 'Analysis not found or not authorized' });
        }

        const doc = new PDFDocument();
        const filename = `analysis_report_${req.params.id}.pdf`;

        res.setHeader('Content-disposition', 'attachment; filename="' + filename + '"');
        res.setHeader('Content-type', 'application/pdf');

        doc.pipe(res);

        doc.fontSize(25).text('Code Analysis Report', {
            align: 'center',
        });
        doc.moveDown();

        doc.fontSize(12).text(`Date: ${new Date(analysis.timestamp).toLocaleString()}`);
        doc.moveDown();

        doc.fontSize(16).text('Original Code:', { underline: true });
        doc.fontSize(10).font('Courier').text(analysis.originalCode, {
            width: 500,
            align: 'left',
            indent: 20,
        });
        doc.moveDown();

        doc.fontSize(16).font('Helvetica').text(`Issues (${analysis.issues.length}):`, { underline: true });
        if (analysis.issues.length > 0) {
            analysis.issues.forEach((issue) => {
                doc.fontSize(10).text(`  - [${issue.type.toUpperCase()}] ${issue.message} (Line: ${issue.line || 'N/A'})`, { indent: 20 });
            });
        } else {
            doc.fontSize(10).text('  No issues found.', { indent: 20 });
        }
        doc.moveDown();

        doc.fontSize(16).text(`Enhancement Suggestions (${analysis.suggestions.length}):`, { underline: true });
        if (analysis.suggestions.length > 0) {
            analysis.suggestions.forEach((sugg) => {
                doc.fontSize(10).text(`  - ${sugg.message}`, { indent: 20 });
            });
        } else {
            doc.fontSize(10).text('  No suggestions.', { indent: 20 });
        }

        doc.end();

    } catch (err) {
        console.error('Error generating PDF report:', err);
        res.status(500).json({ msg: `Failed to generate report: ${err.message}` });
    }
});

// @route   PUT api/analysis/:id
// @desc    Update an analysis entry
// @access  Private (requires authMiddleware)
router.put('/:id', authMiddleware, async (req, res) => {
    const { code } = req.body;
    const userId = req.user.id;

    if (!code) {
        return res.status(400).json({ msg: 'Code is required for update analysis' });
    }

    try {
        let analysis = await Analysis.findById(req.params.id);

        if (!analysis || analysis.userId !== userId) {
            return res.status(404).json({ msg: 'Analysis not found or not authorized' });
        }

        const { issues, suggestions } = await runStaticAnalysis(code);

        analysis.originalCode = code;
        analysis.issues = issues;
        analysis.suggestions = suggestions;
        analysis.timestamp = new Date();

        await analysis.save();

        res.json(analysis);

    } catch (err) {
        console.error('Error updating analysis:', err);
        res.status(500).json({ msg: `Failed to update analysis: ${err.message}` });
    }
});


// @route   DELETE api/analysis/:id
// @desc    Delete an analysis entry
// @access  Private (requires authMiddleware)
router.delete('/:id', authMiddleware, async (req, res) => {
    const userId = req.user.id;

    try {
        const analysis = await Analysis.findById(req.params.id);

        if (!analysis || analysis.userId !== userId) {
            return res.status(404).json({ msg: 'Analysis not found or not authorized' });
        }

        await Analysis.deleteOne({ _id: req.params.id });

        res.json({ msg: 'Analysis removed' });
    } catch (err) {
        console.error('Error deleting analysis:', err);
        res.status(500).json({ msg: `Failed to delete analysis: ${err.message}` });
    }
});

module.exports = router;
