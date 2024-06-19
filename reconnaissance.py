import socket
import whois
import requests
import shodan
import argparse
import dns.resolver


argparse = argparse.ArgumentParser(description="this is tool for reconn.",usage="you can use for find info")
argparse.add_argument("-d","--Domain",help="give domain name for reconnaissance")
argparse.add_argument("-i","--IP",help="give IP Address name for Shodan reconnaissance")
argparse.add_argument("-o","--output",help="give IP Address name for Shodan reconnaissance")

args = argparse.parse_args()
domain = args.Domain
ip = args.IP
output = args.output

print(" [+] your Domain is {} and ip {}".format(domain,ip))
print(" [+] getting whois info...")
py = whois.query(domain=domain)
#whois info.
whois_result=''
whois_result += "Name: {}".format(py.name) +'\n'
whois_result += "Registrar: {} ".format(py.registrar) +'\n'
whois_result += "Creation Date: {}".format(py.creation_date) +'\n'
whois_result += "Expiration date: {}".format(py.expiration_date) +'\n'
whois_result += "Registrant: {}".format(py.registrant) +'\n'
whois_result += "Registrant Country: {}".format(py.registrant_country) +'\n \n'
print(whois_result)
#dnslookup
dns_result=''
try:
    for a in dns.resolver.resolve(domain,'A'):
        dns_result+=" [+] A Record: {}" .format(a.to_text())+'\n'
except:
    print("dns A lookup not found")
try:
    for ns in dns.resolver.resolve(domain, 'NS'):
        dns_result+=" [+] NS Record: {}" .format(ns.to_text())+'\n'
except:
    print("dns NS lookup not found")
try:
    for mx in dns.resolver.resolve(domain,'MX'):
        dns_result+=" [+] MX Record: {}" .format(mx.to_text())+'\n'
except:
    print("dns MX lookup not found")
try:
    for txt in dns.resolver.resolve(domain,'TXT'):
        dns_result+=" [+] TXT Record: {}" .format(txt.to_txt())+'\n\n'
except:
    print("dns TXT lookup not found")
print(dns_result)
#geo location
geo_result=''
try:
    ip1=socket.gethostbyname(domain)
    response = requests.request('GET',"https://geolocation-db.com/json/" + str(ip1)).json()
    geo_result+= "[+]Country is : {}" .format(response['country_name'])+'\n'
    geo_result+= "[+]Lattitude is: {}".format(response['latitude'])+'\n'
    geo_result+= "[+]longitude is : {}".format(response['longitude'])+'\n'
    geo_result+= "[+]City is : {}".format(response["city"])+'\n'
    geo_result+= "[+]State is : {}".format(response['state'])+'\n'
    geo_result+= "[+]IPv4 is : {}".format(response['IPv4'])+'\n'
    geo_result+= "[+]postal is : {}".format(response['postal'])+'\n'
    geo_result+= "[+]country_code is : {}".format(response['country_code'])+'\n\n'
except:
    print("geoloction is not found")
    pass
#shodan
key = ""
if ip:
    print("enter you api key")
    input(key)
    if key:
        api = shodan.Shodan(key)
        try:
            shodan_result=''
            result = api.search(ip)
            print("[+] results found : {}".format(result['total']))
            for results in result['matches']:
                shodan_result+="[+] ip :" .format(result['ip_str'])
                shodan_result+="[+] data : \n {} \n" .format(result['data'])
        except:
            print("[-] shodan search error.")

        print(shodan_result)
if output:

    with open(output,'w') as file:
        try:
            file.write(whois_result)
        except:
            pass
        try:
            file.write(dns_result)
        except:
            pass
        try:
            file.write(geo_result)
        except:
            pass
        try:
            file.write(shodan_result)
        except:
            pass
