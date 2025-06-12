# Use a Node.js base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
# This step only runs if package.json or package-lock.json changes
COPY package*.json ./

# Install backend dependencies with npm ci, cache clean, reduced timeout, and limited retries
# This command will first clean the npm cache to avoid corrupted downloads.
# Then, it sets a global npm timeout for the current execution to 1 minute (60000ms).
# It uses `npm ci` for a faster, clean install from package-lock.json.
# If `npm ci` fails (returns a non-zero exit code), it will loop up to 3 times.
# In each retry, it will sleep for `retry_count` seconds before retrying.
# If `npm ci` succeeds at any point, the loop breaks.
# If all retries fail, the entire RUN command will fail.
RUN npm cache clean --force \
    && npm config set fetch-timeout 60000 \
    && npm ci || retry=1 && while [ $retry -le 3 ]; do sleep $retry; npm ci && break || retry=$((retry+1)); done

# Copy the rest of the backend application code
COPY . .

# Expose the port your Express app runs on (e.g., 5000 as per your server.js)
EXPOSE 5000

# Command to run the application
# Use 'npm start' as defined in your package.json
CMD ["npm", "start"]
