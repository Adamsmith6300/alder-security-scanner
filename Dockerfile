# syntax=docker/dockerfile:1

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Declare build arguments for API keys
ARG GOOGLE_API_KEY
ARG OPENAI_API_KEY

# Set environment variables from build arguments
ENV GOOGLE_API_KEY=$GOOGLE_API_KEY
ENV OPENAI_API_KEY=$OPENAI_API_KEY

# Install git and other dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
COPY src/ /app/src/

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Define the entrypoint and default command
ENTRYPOINT ["/entrypoint.sh"]
CMD []
