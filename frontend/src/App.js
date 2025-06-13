import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
    LogIn,
    LayoutDashboard,
    History,
    FileText,
    Download,
    Trash2,
    Edit,
    Code,
    AlertTriangle,
    Lightbulb,
    CheckCircle,
    XCircle,
    BookOpen,
    HelpCircle // Added for modal icon
} from "lucide-react";

// --- Global Constants (for easier management) ---
const API_BASE_URL = "http://localhost:5000/api"; // IMPORTANT: Replace with your deployed backend URL in production!

// --- Custom Modal Component (replaces window.confirm) ---
const CustomModal = ({ isOpen, title, message, onConfirm, onCancel, confirmText = "Confirm", cancelText = "Cancel" }) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-75 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-xl shadow-2xl p-6 w-full max-w-sm border border-gray-200">
                <div className="flex items-center mb-4">
                    <HelpCircle className="text-blue-500 mr-3" size={24} />
                    <h3 className="text-xl font-bold text-gray-900">{title}</h3>
                </div>
                <p className="text-gray-700 mb-6">{message}</p>
                <div className="flex justify-end space-x-3">
                    <button
                        onClick={onCancel}
                        className="px-5 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition duration-150 ease-in-out font-medium"
                    >
                        {cancelText}
                    </button>
                    <button
                        onClick={onConfirm}
                        className="px-5 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-150 ease-in-out shadow-md font-medium"
                    >
                        {confirmText}
                    </button>
                </div>
            </div>
        </div>
    );
};

// --- Main App Component ---
const App = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null); // User object from backend authentication
    const [userStorage, setUserStorage] = useState({}); // In-memory storage replacement

    const handleLogin = (userData) => {
        setIsAuthenticated(true);
        setUser(userData);
        // Store user data in memory after successful login
        setUserStorage({
            userToken: userData.token,
            userId: userData.id,
            username: userData.username
        });
    };

    const handleLogout = () => {
        setIsAuthenticated(false);
        setUser(null);
        setUserStorage({}); // Clear in-memory storage on logout
    };

    // Check for existing token in in-memory storage on app load
    useEffect(() => {
        const { userToken, userId, username } = userStorage;
        if (userToken && userId && username) {
            setIsAuthenticated(true);
            setUser({ id: userId, username: username, token: userToken });
        }
    }, [userStorage]);

    // Simple routing logic based on isAuthenticated state
    const renderPage = () => {
        if (!isAuthenticated) {
            return <LoginPage onLogin={handleLogin} />;
        } else {
            return <DashboardPage user={user} onLogout={handleLogout} />;
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-100 to-gray-200 font-inter text-gray-800">
            {renderPage()}
        </div>
    );
};

// --- Login Page Component ---
const LoginPage = ({ onLogin }) => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [isRegister, setIsRegister] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setIsLoading(true);

        try {
            const authEndpoint = isRegister ? `${API_BASE_URL}/auth/register` : `${API_BASE_URL}/auth/login`;
            console.log("1. Sending request to:", authEndpoint);
            const authResponse = await fetch(authEndpoint, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            const authData = await authResponse.json();
            console.log("2. Auth response received:", authResponse);
            console.log("3. Auth data parsed (from register/login):", authData); // <<< IMPORTANT LOG

            if (!authResponse.ok) {
                setError(authData.msg || "Authentication failed. Please check credentials.");
                console.error("4. Authentication failed (register/login) response:", authData);
                return;
            }

            // Successfully authenticated, now check for token and fetch user details
            const token = authData.token;
            console.log("5. Token received:", token);

            if (!token) {
                setError("Authentication successful, but no token received in response.");
                console.error("6. Error: No token in authData:", authData);
                return;
            }

            // Fetch user details using the received token
            console.log("7. Fetching user details with token...");
            const userDetailsResponse = await fetch(`${API_BASE_URL}/auth/user`, {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${token}`,
                },
            });

            const userDetails = await userDetailsResponse.json();
            console.log("8. User details response received:", userDetailsResponse);
            console.log("9. User details parsed:", userDetails); // <<< IMPORTANT LOG

            if (userDetailsResponse.ok) {
                // Pass both token and user details to onLogin
                onLogin({ id: userDetails._id || userDetails.id, username: userDetails.username, token: token });
                console.log("10. Login successful, user data sent to App:", { id: userDetails._id || userDetails.id, username: userDetails.username, token: token });
            } else {
                // If fetching user details fails after token, something is wrong with token or /user route
                setError(userDetails.msg || "Could not retrieve user details after authentication.");
                console.error("11. Error retrieving user details:", userDetails);
                // Optionally log out locally to prevent invalid state if /user route is critical
                onLogin(null);
            }

        } catch (err) {
            console.error("12. General fetch error (network/parsing):", err);
            setError("Could not connect to server. Please try again later.");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen p-4">
            <form onSubmit={handleSubmit} className="bg-white p-8 rounded-xl shadow-2xl w-full max-w-md border border-gray-200">
                <h2 className="text-3xl font-bold text-center text-gray-900 mb-8">
                    <LogIn className="inline-block mr-2 text-blue-600" size={30} />
                    {isRegister ? "Register" : "Welcome Back"}
                </h2>
                <div className="space-y-6">
                    <div>
                        <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                        <input
                            type="text"
                            id="username"
                            className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                            placeholder="Enter your username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            disabled={isLoading}
                        />
                    </div>
                    <div>
                        <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                        <input
                            type="password"
                            id="password"
                            className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                            placeholder="Enter your password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            disabled={isLoading}
                        />
                    </div>
                    {error && <p className="text-red-600 text-sm text-center">{error}</p>}
                    <button
                        type="submit"
                        className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 shadow-lg transition duration-300 ease-in-out transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                        disabled={isLoading}
                    >
                        {isLoading ? (
                            <svg className="animate-spin h-5 w-5 mx-auto text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                        ) : (
                            isRegister ? "Register" : "Log In"
                        )}
                    </button>
                </div>
                <p className="mt-6 text-center text-gray-600">
                    {isRegister ? "Already have an account?" : "Don't have an account?"}{" "}
                    <button
                        type="button"
                        onClick={() => setIsRegister(!isRegister)}
                        className="text-blue-600 hover:text-blue-800 font-semibold transition duration-150"
                        disabled={isLoading}
                    >
                        {isRegister ? "Login here" : "Register here"}
                    </button>
                </p>
            </form>
        </div>
    );
};

// --- Dashboard Page Component ---
const DashboardPage = ({ user, onLogout }) => {
    const [activeTab, setActiveTab] = useState("analyze"); // "analyze" or "history"
    const [code, setCode] = useState("");
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [analysisHistory, setAnalysisHistory] = useState([]);
    const [editMode, setEditMode] = useState(null); // Stores the ID of the item being edited
    const [errorMessage, setErrorMessage] = useState(""); // For general error messages

    // State for the custom confirmation modal
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [modalAction, setModalAction] = useState(null); // Function to execute on confirm
    const [modalItemId, setModalItemId] = useState(null); // Item ID for delete/update

    // API utility object, memoized to prevent re-creation on every render
    const api = useMemo(() => ({
        // Helper to get authorization headers
        getAuthHeaders: () => ({
            "Content-Type": "application/json",
            "Authorization": `Bearer ${user.token}`, // Pass the JWT token
        }),

        analyzeCode: async (codeContent) => {
            const response = await fetch(`${API_BASE_URL}/analysis`, {
                method: "POST",
                headers: api.getAuthHeaders(),
                body: JSON.stringify({ code: codeContent }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || "Failed to analyze code");
            }
            return response.json();
        },

        getHistory: async () => {
            const response = await fetch(`${API_BASE_URL}/analysis/history`, {
                method: "GET",
                headers: api.getAuthHeaders(),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || "Failed to fetch history");
            }
            return response.json();
        },

        deleteAnalysis: async (id) => {
            const response = await fetch(`${API_BASE_URL}/analysis/${id}`, {
                method: "DELETE",
                headers: api.getAuthHeaders(),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || "Failed to delete analysis");
            }
            return response.json();
        },

        updateAnalysis: async (id, updatedCode) => {
            const response = await fetch(`${API_BASE_URL}/analysis/${id}`, {
                method: "PUT",
                headers: api.getAuthHeaders(),
                body: JSON.stringify({ code: updatedCode }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || "Failed to update analysis");
            }
            return response.json();
        },

        downloadPDFReport: async (id) => {
            const response = await fetch(`${API_BASE_URL}/analysis/report/${id}`, {
                method: "GET",
                headers: api.getAuthHeaders(),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || "Failed to download report");
            }
            // Trigger file download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `analysis_report_${id}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        }
    }), [user.token]);

    const fetchHistory = useCallback(async () => {
        try {
            const history = await api.getHistory();
            setAnalysisHistory(history);
            setErrorMessage("");
        } catch (error) {
            setErrorMessage(`Error fetching history: ${error.message}`);
        }
    }, [api]);

    useEffect(() => {
        if (user && user.id && user.token) {
            fetchHistory();
        }
    }, [user, fetchHistory]);

    const handleAnalyze = async () => {
        if (!code.trim()) {
            setErrorMessage("Please paste code to analyze.");
            return;
        }
        setIsLoading(true);
        setAnalysisResult(null);
        setErrorMessage("");
        try {
            const result = await api.analyzeCode(code);
            setAnalysisResult(result);
            fetchHistory();
            setCode("");
            setEditMode(null);
        } catch (error) {
            setErrorMessage(`Failed to analyze code: ${error.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    const handleDownloadPDF = async () => {
        if (!analysisResult) {
            setErrorMessage("Please analyze code first to generate a report.");
            return;
        }
        try {
            await api.downloadPDFReport(analysisResult._id);
            setErrorMessage("");
        } catch (error) {
            setErrorMessage(`Failed to download PDF report: ${error.message}`);
        }
    };

    const confirmDeleteAnalysis = (id) => {
        setModalItemId(id);
        setModalAction(() => () => performDeleteAnalysis(id));
        setIsModalOpen(true);
    };

    const performDeleteAnalysis = async (id) => {
        setIsLoading(true);
        setErrorMessage("");
        try {
            await api.deleteAnalysis(id);
            fetchHistory();
            if (analysisResult && analysisResult._id === id) {
                setAnalysisResult(null);
            }
            setEditMode(null);
            setCode("");
            setIsModalOpen(false);
        } catch (error) {
            setErrorMessage(`Failed to delete analysis: ${error.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    const handleEditClick = (item) => {
        setEditMode(item._id);
        setCode(item.originalCode);
        setActiveTab("analyze");
        setAnalysisResult(null);
        setErrorMessage("");
    };

    const handleUpdateAnalysis = async (id) => {
        if (!code.trim()) {
            setErrorMessage("Code cannot be empty for update.");
            return;
        }
        setIsLoading(true);
        setErrorMessage("");
        try {
            const updatedResult = await api.updateAnalysis(id, code);
            setAnalysisResult(updatedResult);
            setEditMode(null);
            setCode("");
            fetchHistory();
        } catch (error) {
            setErrorMessage(`Failed to update analysis: ${error.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex flex-col min-h-screen">
            {/* Header */}
            <header className="bg-white shadow-md p-4 flex justify-between items-center z-10">
                <h1 className="text-3xl font-extrabold text-blue-700 flex items-center">
                    <BookOpen className="inline-block mr-3 text-blue-600" size={36} />
                    CodeChecker & Enhancer
                </h1>
                <div className="flex items-center space-x-4">
                    {user?.username && <span className="text-lg font-medium text-gray-700">Welcome, {user.username}!</span>}
                    <button
                        onClick={onLogout}
                        className="flex items-center px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition duration-300 ease-in-out shadow-md hover:shadow-lg"
                    >
                        <LogIn className="mr-2" size={18} />
                        Logout
                    </button>
                </div>
            </header>

            {/* Error Message Display */}
            {errorMessage && (
                <div className="mx-6 mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <div className="flex items-center">
                        <AlertTriangle className="mr-2 text-red-500" size={20} />
                        <span className="text-red-700">{errorMessage}</span>
                        <button
                            onClick={() => setErrorMessage("")}
                            className="ml-auto text-red-500 hover:text-red-700"
                        >
                            <XCircle size={20} />
                        </button>
                    </div>
                </div>
            )}

            {/* Main Content Area */}
            <div className="flex flex-1 p-6 space-x-6">
                {/* Sidebar Navigation */}
                <nav className="w-64 bg-white p-6 rounded-xl shadow-lg border border-gray-200 h-fit">
                    <ul className="space-y-4">
                        <li>
                            <button
                                onClick={() => setActiveTab("analyze")}
                                className={`w-full flex items-center p-3 rounded-lg text-lg font-semibold transition duration-200 ease-in-out ${
                                    activeTab === "analyze" ? "bg-blue-600 text-white shadow-md" : "text-gray-700 hover:bg-blue-100 hover:text-blue-700"
                                }`}
                            >
                                <Code className="mr-3" size={20} />
                                Analyze Code
                            </button>
                        </li>
                        <li>
                            <button
                                onClick={() => setActiveTab("history")}
                                className={`w-full flex items-center p-3 rounded-lg text-lg font-semibold transition duration-200 ease-in-out ${
                                    activeTab === "history" ? "bg-blue-600 text-white shadow-md" : "text-gray-700 hover:bg-blue-100 hover:text-blue-700"
                                }`}
                            >
                                <History className="mr-3" size={20} />
                                Analysis History
                            </button>
                        </li>
                    </ul>
                </nav>

                {/* Content Panel */}
                <div className="flex-1 bg-white p-8 rounded-xl shadow-lg border border-gray-200">
                    {activeTab === "analyze" && (
                        <div className="flex flex-col h-full">
                            <h2 className="text-3xl font-bold text-gray-900 mb-6 flex items-center">
                                <FileText className="mr-3 text-blue-600" size={28} />
                                Code Analysis
                            </h2>
                            <textarea
                                className="w-full flex-1 p-4 border border-gray-300 rounded-lg shadow-sm focus:ring-blue-500 focus:border-blue-500 font-mono text-sm resize-y min-h-[200px]"
                                placeholder="Paste your code here..."
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                            ></textarea>
                            <div className="mt-6 flex space-x-4">
                                <button
                                    onClick={editMode ? () => handleUpdateAnalysis(editMode) : handleAnalyze}
                                    className="flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 shadow-lg transition duration-300 ease-in-out transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                                    disabled={isLoading}
                                >
                                    {isLoading ? (
                                        <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                    ) : (
                                        editMode ? <Edit className="mr-2" size={20} /> : <FileText className="mr-2" size={20} />
                                    )}
                                    {editMode ? "Update Analysis" : "Analyze Code"}
                                </button>
                                <button
                                    onClick={handleDownloadPDF}
                                    className="flex items-center px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 shadow-lg transition duration-300 ease-in-out transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                                    disabled={!analysisResult || isLoading}
                                >
                                    <Download className="mr-2" size={20} />
                                    Download PDF Report
                                </button>
                            </div>

                            {analysisResult && (
                                <div className="mt-8 p-6 bg-gray-50 rounded-lg border border-gray-200 shadow-inner">
                                    <h3 className="text-2xl font-bold text-gray-900 mb-4 flex items-center">
                                        <LayoutDashboard className="mr-2 text-blue-600" size={24} />
                                        Analysis Results
                                    </h3>

                                    {/* Issues */}
                                    <div className="mb-6">
                                        <h4 className="text-xl font-semibold text-gray-800 mb-3 flex items-center">
                                            <AlertTriangle className="mr-2 text-red-500" size={22} />
                                            Issues ({analysisResult.issues.length})
                                        </h4>
                                        {analysisResult.issues.length > 0 ? (
                                            <ul className="space-y-2">
                                                {analysisResult.issues.map((issue, index) => (
                                                    <li key={index} className="flex items-start text-red-700">
                                                        <XCircle className="mt-1 mr-2 flex-shrink-0" size={18} />
                                                        <span>
                                                            <span className="font-medium">[{issue.type.toUpperCase()}]</span> {issue.message} (Line: {issue.line || "N/A"})
                                                        </span>
                                                    </li>
                                                ))}
                                            </ul>
                                        ) : (
                                            <p className="text-gray-600 flex items-center">
                                                <CheckCircle className="mr-2 text-green-500" size={20} />
                                                No critical issues found!
                                            </p>
                                        )}
                                    </div>

                                    {/* Suggestions */}
                                    <div>
                                        <h4 className="text-xl font-semibold text-gray-800 mb-3 flex items-center">
                                            <Lightbulb className="mr-2 text-yellow-500" size={22} />
                                            Enhancement Suggestions ({analysisResult.suggestions.length})
                                        </h4>
                                        {analysisResult.suggestions.length > 0 ? (
                                            <ul className="space-y-2">
                                                {analysisResult.suggestions.map((sugg, index) => (
                                                    <li key={index} className="flex items-start text-blue-700">
                                                        <Lightbulb className="mt-1 mr-2 flex-shrink-0" size={18} />
                                                        <span>{sugg.message}</span>
                                                    </li>
                                                ))}
                                            </ul>
                                        ) : (
                                            <p className="text-gray-600">No specific enhancement suggestions at this time.</p>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === "history" && (
                        <div>
                            <h2 className="text-3xl font-bold text-gray-900 mb-6 flex items-center">
                                <History className="mr-3 text-blue-600" size={28} />
                                Analysis History
                            </h2>
                            {analysisHistory.length > 0 ? (
                                <div className="space-y-6">
                                    {analysisHistory.map((item) => (
                                        <HistoryItem
                                            key={item._id}
                                            item={item}
                                            onDelete={() => confirmDeleteAnalysis(item._id)}
                                            onEdit={() => handleEditClick(item)}
                                        />
                                    ))}
                                </div>
                            ) : (
                                <div className="bg-gray-50 p-6 rounded-lg border border-gray-200 text-center text-gray-600 text-lg">
                                    No analysis history found. Start by analyzing some code!
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Custom Delete Confirmation Modal */}
            <CustomModal
                isOpen={isModalOpen}
                title="Confirm Deletion"
                message="Are you sure you want to delete this analysis? This action cannot be undone."
                onConfirm={() => {
                    if (modalAction) modalAction();
                    setIsModalOpen(false);
                    setModalAction(null);
                    setModalItemId(null);
                }}
                onCancel={() => {
                    setIsModalOpen(false);
                    setModalAction(null);
                    setModalItemId(null);
                }}
                confirmText="Delete"
                cancelText="Cancel"
            />
        </div>
    );
};

// --- History Item Component ---
const HistoryItem = ({ item, onDelete, onEdit }) => {
    const [showCode, setShowCode] = useState(false);

    return (
        <div className="bg-gray-50 p-6 rounded-xl shadow-md border border-gray-200">
            <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-semibold text-gray-800">
                    Analysis on {new Date(item.timestamp).toLocaleString()}
                </h3>
                <div className="flex space-x-2">
                    <button
                        onClick={() => setShowCode(!showCode)}
                        className="flex items-center px-3 py-1 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition duration-150 text-sm"
                    >
                        {showCode ? "Hide Code" : "Show Code"}
                        <Code className="ml-2" size={16} />
                    </button>
                    <button
                        onClick={onEdit}
                        className="flex items-center px-3 py-1 bg-yellow-500 text-white rounded-md hover:bg-yellow-600 transition duration-150 text-sm"
                    >
                        Edit
                        <Edit className="ml-2" size={16} />
                    </button>
                    <button
                        onClick={onDelete}
                        className="flex items-center px-3 py-1 bg-red-500 text-white rounded-md hover:bg-red-600 transition duration-150 text-sm"
                    >
                        Delete
                        <Trash2 className="ml-2" size={16} />
                    </button>
                </div>
            </div>
            {showCode && (
                <div className="mt-4 mb-4">
                    <h4 className="font-medium text-gray-700 mb-2">Original Code:</h4>
                    <pre className="bg-gray-100 p-3 rounded-md border border-gray-200 text-sm font-mono max-h-40 overflow-auto whitespace-pre-wrap">
                        {item.originalCode}
                    </pre>
                </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <h4 className="font-medium text-gray-700 flex items-center mb-2">
                        <AlertTriangle className="mr-2 text-red-500" size={18} />
                        Issues:
                    </h4>
                    {item.issues && item.issues.length > 0 ? (
                        <ul className="list-disc list-inside text-red-600 space-y-1">
                            {item.issues.map((issue, index) => (
                                <li key={index} className="text-sm">
                                    <span className="font-semibold">[{issue.type.toUpperCase()}]</span> {issue.message} (Line: {issue.line || "N/A"})
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="text-gray-600 text-sm">No issues found.</p>
                    )}
                </div>
                <div>
                    <h4 className="font-medium text-gray-700 flex items-center mb-2">
                        <Lightbulb className="mr-2 text-yellow-500" size={18} />
                        Suggestions:
                    </h4>
                    {item.suggestions && item.suggestions.length > 0 ? (
                        <ul className="list-disc list-inside text-blue-600 space-y-1">
                            {item.suggestions.map((sugg, index) => (
                                <li key={index} className="text-sm">{sugg.message}</li>
                            ))}
                        </ul>
                    ) : (
                        <p className="text-gray-600 text-sm">No suggestions.</p>
                    )}
                </div>
            </div>
        </div>
    );
};

export default App;
