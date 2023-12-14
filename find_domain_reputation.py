'''
find the domain reputation for these domain names
'''

import socket
import requests

ifile = 'domains_mac_march_21'
# ofile = open('domains-ubuntu.csv', 'a') 
virus_total_api_key = "2ae84879f15a361483dd9cc2434e0376961261ef93413f02a5ce1a0200698af5"
url = 'https://www.virustotal.com/api/v3/domains/'


def find_domain_reputation(domain_name):
    # find the domain reputation for these domain names
    params = {'apikey': virus_total_api_key, 'domain': domain_name}
    response = requests.get(url, params=params)

    fire_url = url + domain_name
    headers = {
        'x-apikey': virus_total_api_key,
        'Accept': 'application/json'
    }
    response = requests.get(fire_url, headers=headers)
    response_data = response.json()
    
    if 'data' not in response_data:
        print(domain_name + ' No data')
        return
    
    for k in response_data['data']['attributes']['last_analysis_results'].keys():
        rep = response_data['data']['attributes']['last_analysis_results'][k]['category']
        if rep == 'harmless' or rep == 'undetected':
            continue
        else:
            print("COULD BE MALICIOUS")
            print(domain_name, rep)


with open(ifile) as f:
    for line in f:
        domain = line.strip()
        # print(domain)
        find_domain_reputation(domain)