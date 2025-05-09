# Use an official Python image as a base
FROM python:3.10

# Set the working directory inside the container
WORKDIR /

# Copy only the requirements file to leverage Docker caching
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port FastAPI runs on
EXPOSE 8000

# Run FastAPI using Uvicorn
CMD ["python3", "app/main.py"]
