# Use a Node.js base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
# This step only runs if package.json or package-lock.json changes
COPY package*.json ./

# Install backend dependencies with retry logic
# This command will attempt to run `npm install`.
# If `npm install` fails (returns a non-zero exit code), it will loop up to 5 times.
# In each retry, it will sleep for `retry_count * 2` seconds before retrying.
# If `npm install` succeeds at any point, the loop breaks.
# If all retries fail, the entire RUN command will fail.
RUN npm install || retry=1 && while [ $retry -le 5 ]; do sleep $((retry*2)); npm install && break || retry=$((retry+1)); done

# Copy the rest of the backend application code
COPY . .

# Expose the port your Express app runs on (e.g., 5000 as per your server.js)
EXPOSE 5000

# Command to run the application
# Use 'npm start' as defined in your package.json
CMD ["npm", "start"]
