# Stage 1: Build the React application
FROM node:20-alpine AS build

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies with npm ci, cache clean, reduced timeout, and limited retries
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

# Copy the rest of the application code
COPY . .

# Build the React app for production
# This will create a 'build' folder with static assets
RUN npm run build

# Stage 2: Serve the React application with Nginx
FROM nginx:alpine

# Copy the built React app from the build stage to Nginx's public directory
COPY --from=build /app/build /usr/share/nginx/html

# Copy a custom Nginx configuration (optional, but good for SPAs)
# If you have a custom nginx.conf for React routing (e.g., for direct URL access)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 for the web server
EXPOSE 80

# Command to start Nginx
CMD ["nginx", "-g", "daemon off;"]
