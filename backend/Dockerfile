# Use a Node.js base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
# This step only runs if package.json or package-lock.json changes
COPY package*.json ./

# Install backend dependencies
RUN npm install

# Copy the rest of the backend application code
COPY . .

# Expose the port your Express app runs on (e.g., 5000 as per your server.js)
EXPOSE 5000

# Command to run the application
# Use 'npm start' as defined in your package.json
CMD ["npm", "start"]