import json
import requests

# Base URL for the API endpoints
base_url = "http://localhost:8111/api/v1"

# List of paths to scan
paths = [
    "/configmaps",
    "/pods",
    "/secrets"
]

# Function to fetch data from an API endpoint and return the response as JSON
def fetch_api_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None

# Dictionary to store the responses
responses = {}

# Fetch data from each path and store it in the responses dictionary
for path in paths:
    url = f"{base_url}{path}"
    api_response = fetch_api_data(url)
    if api_response is not None:
        responses[path] = api_response

# Save the responses to a JSON file
with open('api_responses_k8s_scan.json', 'w') as response_file:
    json.dump(responses, response_file, indent=4)

print("API responses have been saved to api_responses.json")

# Fetch detailed information for each item in the 'rows' of the responses
detailed_responses = {}

for path, data in responses.items():
    detailed_responses[path] = []
    for item in data.get("rows", []):
        resource_url = f"{base_url}{path}/{item['metadata']['name']}"
        detailed_response = fetch_api_data(resource_url)
        if detailed_response is not None:
            detailed_responses[path].append(detailed_response)

# Save the detailed responses to a JSON file
with open('detailed_api_responses.json', 'w') as detailed_response_file:
    json.dump(detailed_responses, detailed_response_file, indent=4)

print("Detailed API responses have been saved to detailed_api_responses.json")
