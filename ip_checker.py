import requests
from dotenv import load_dotenv
import os



# Function to check the IP address using AbuseIPDB API
def check_ip_abuse(ip_address, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip_address,
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    # Sending GET request to AbuseIPDB API
    response = requests.get(url, headers=headers, params=querystring)
    
    # Check if the response is successful
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to retrieve data. Status code: {response.status_code}"}
    
# Function to print the result
def print_result(result):
    if "data" in result:
        for key, value in result["data"].items():
            print(f"{key}: {value}\n")
    else:
        print("Error: ", result.get("error", "Unknown error"))


def main():
    # Get the IP address from the user
    ip_address = input("Please enter an IP address: ")

    # Load abuseipdb api key from env file
    load_dotenv()
    
    # Get the relevant API key
    api_key = os.getenv("abuseipdb_api_key")
    
    # Get the information about the IP address
    result = check_ip_abuse(ip_address, api_key)
    
    # Print the information
    print_result(result)

if __name__ == "__main__":
    main()