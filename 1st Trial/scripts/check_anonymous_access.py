import requests
import urllib3
from requests.exceptions import RequestException

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_anonymous_access(api_server_url):
    try:
        # Define the URL for the API server endpoint
        url = f'{api_server_url}/api/v1/nodes'

        # Make an unauthenticated request
        response = requests.get(url, verify=False)  # not verifying SSL for simplicity

        # Check the response status code
        if response.status_code == 200:
            print("Anonymous API access is enabled. This is a security risk.")
        elif response.status_code == 401 or response.status_code == 403:
            print("Anonymous API access is not enabled. Access denied as expected.")
        else:
            print(f"Received unexpected status code: {response.status_code}")
    except RequestException as e:
        print(f"Exception when checking anonymous API access: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == '__main__':
    # Replace with your Kubernetes API server URL
    api_server_url = 'https://127.0.0.1:59665'
    check_anonymous_access(api_server_url)
