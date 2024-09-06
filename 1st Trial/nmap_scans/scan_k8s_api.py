import json
import requests

# Function to fetch data from API and return the response as JSON
def fetch_api_data(base_url, path):
    url = f"{base_url}{path}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None

# Read the list of API paths from a JSON file
with open('api_paths_fromScan.json', 'r') as api_file:
    data = json.load(api_file)
    api_paths = data['paths']

# Base URL for the API (you can change it to your actual base URL)
base_url = "http://example.com"

# Dictionary to store the responses
responses = {}

# Fetch data from each API and store it in the responses dictionary
for path in api_paths:
    api_response = fetch_api_data(base_url, path)
    if api_response is not None:
        responses[path] = api_response

# Save the responses to a new JSON file
with open('api_responses_pathScan.json', 'w') as response_file:
    json.dump(responses, response_file, indent=4)

print("API responses have been saved to api_responses.json")
