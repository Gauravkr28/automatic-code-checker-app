import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

// REMOVED: Dynamic injection of Tailwind CSS and Font Inter
// These are now directly in public/index.html for immediate loading.
// const styleSheet = `
//   @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap");
//   body {
//     font-family: "Inter", sans-serif;
//   }
// `;
// const styleElement = document.createElement("style");
// styleElement.innerHTML = styleSheet;
// document.head.appendChild(styleElement);

// const tailwindScript = document.createElement("script");
// tailwingScript.src = "https://cdn.tailwindcss.com";
// document.head.appendChild(tailwindScript);

// Get the root DOM element where your React app will be mounted
const container = document.getElementById("root");

// Create a root for React 18+ concurrent mode
const root = createRoot(container);

// Render your App component into the root
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
