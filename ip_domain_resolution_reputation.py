'''
resolve the ip address to domain name
find the domain reputation for these domain names
'''

import socket
import requests

ofile = open('resolved-mac.csv', 'a') 

ips = ["34.68.90.188", "88.214.26.53", "212.70.149.38", "170.39.218.4", "91.210.107.28", "134.209.37.160", "134.122.51.63", "176.111.174.85", "179.60.147.156", "162.142.125.248", "239.255.255.250", "176.111.174.95", "23.45.233.35", "224.0.0.251", "17.253.144.10", "224.0.0.252", "192.229.211.108", "255.255.255.255", "0.0.0.0"]
virus_total_api_key = "2ae84879f15a361483dd9cc2434e0376961261ef93413f02a5ce1a0200698af5"
# url = 'https://www.virustotal.com/vtapi/v2/domain/report'

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
    # print(response_data)
    print()
    for k in response_data['data']['attributes']['last_analysis_results'].keys():
        print(response_data['data']['attributes']['last_analysis_results'][k]['category'], end=" ")


def ip_domain_resolution(ips):
    # resolve the ip address to domain name
    domain_names = []
    for ip in ips:
        print('\n\n' + str(ip))
        try:
            domain_name = socket.gethostbyaddr(ip)
            print(ip, domain_name[0])
            ofile.write("{}, {} \n".format(ip, domain_name[0]))
            find_domain_reputation(domain_name[0])
        except socket.herror:
            print("No domain name found for this ip address")
            ofile.write("{}, None \n".format(ip))


        
ip_domain_resolution(ips)
