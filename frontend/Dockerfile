# Stage 1: Build the React application
FROM node:20-alpine AS build

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies with retry logic
# This command will attempt to run `npm install`.
# If `npm install` fails (returns a non-zero exit code), it will loop up to 5 times.
# In each retry, it will sleep for `retry_count * 2` seconds before retrying.
# If `npm install` succeeds at any point, the loop breaks.
# If all retries fail, the entire RUN command will fail.
RUN npm install || retry=1 && while [ $retry -le 5 ]; do sleep $((retry*2)); npm install && break || retry=$((retry+1)); done

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
