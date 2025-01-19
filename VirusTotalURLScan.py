import requests
from dotenv import load_dotenv
import os

# Load api key from env file
load_dotenv()

API_KEY = os.getenv("virustotal_api_key")

def analysis_id(url_to_scan):
    #This function gets a valid url from the user and send it to VirusTotal, which response with the analysis id for using with the analysis endpoint.

    scan_id_endpoint = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url_to_scan }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey" : API_KEY
    }

    response = requests.post(scan_id_endpoint, data=payload, headers=headers)
    temp_dic = eval(response.text)
    return temp_dic['data']['id']

def analysis_endpoint(id):
    url = f"https://www.virustotal.com/api/v3/analyses/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    temp = eval(response.text)
    result_dic = {}
    result_dic['URL'] = temp['meta']['url_info']['url']
    result_dic['stats'] = temp['data']['attributes']['stats']
    results = temp['data']['attributes']['results']
    for key in results.keys():
        if results[key]['category'] != 'harmless' and results[key]['category'] != 'undetected':
            result_dic[key] = results[key]

    
    return result_dic

def print_results(result):
    for field in result.items():
        if type(field[1]) == dict:
            print(field[0])
            for x in field[1].keys():
                print('\t', x, ' : ', field[1][x], sep="", end='\n')
            print('\n')
        else:
            print(field[0], ' : ', field[1], sep="")




url_to_scan = input("Please enter a valid URL: ")
url_report = analysis_endpoint(analysis_id(url_to_scan))
print_results(url_report)