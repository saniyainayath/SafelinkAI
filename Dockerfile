# Use an official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy your entire project into the container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app runs on
EXPOSE 5000

# Set the command to run your app with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
