#!/bin/bash

# Define the directory containing YAML files
DIRECTORY="./Mitigation/tetragon/"

# Check if the directory exists
if [ ! -d "$DIRECTORY" ]; then
    echo "Error: Directory $DIRECTORY does not exist."
    exit 1
fi

echo "Applying Tetragon Policies"

# Iterate through all YAML files in the directory
for file in "$DIRECTORY"/*.yaml "$DIRECTORY"/*.yml; do
    # Check if the file exists (handles case where no matching files are found)
    if [ -f "$file" ]; then
        echo "Applying: $file"
        kubectl apply -f "$file"
    fi
done

echo "Tetragon Tracing Policies applied."

echo "Port forwarding grafana"
kubectl port-forward service/monitoring-grafana -n monitoring 8080:80 &
echo "Grafana running on port 8080"