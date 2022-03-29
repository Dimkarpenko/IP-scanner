from pyfiglet import Figlet
import sys
import socket
from datetime import datetime
import dns.resolver
from rich import print
import whois
import ssl
import requests
import os

preview_text = Figlet(font='slant')
banner = preview_text.renderText('IP SCANNER')
print("[#FEC42D]" + banner + "[/#FEC42D]")

#scan dns
def get_records(domain='127.0.0.1'):
    print("[#3B78FF]Scanning DNS records...[/#3B78FF]")
    print("─" * 50)
    ids = [
        'NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
    ]
    
    for a in ids:
        try:
            answers = dns.resolver.resolve(domain, a)
            for rdata in answers:
                print('[#23D18B]' + a + '[/#23D18B]:[#29B8DB]' + rdata.to_text() + "[/#29B8DB]")
    
        except Exception as e:
            pass

    print("─" * 50)

def get_whois(target="127.0.0.1"):
    w = whois.whois(target)
    print("[#3B78FF]Scanning whois...[/#3B78FF]")
    print("─" * 50)
    print(f"[#23D18B]Domain name[/#23D18B]:[#29B8DB]{w.domain_name}[/#29B8DB]")
    print(f"[#23D18B]Registrar[/#23D18B]:[#29B8DB]{w.registrar}[/#29B8DB]")
    print(f"[#23D18B]Whois server[/#23D18B]:[#29B8DB]{w.whois_server}[/#29B8DB]")
    print(f"[#23D18B]Referral url[/#23D18B]:[#29B8DB]{w.referral_url}[/#29B8DB]")
    print(f"[#23D18B]Updated date[/#23D18B]:[#29B8DB]{w.updated_date}[/#29B8DB]")
    print(f"[#23D18B]Creation date[/#23D18B]:[#29B8DB]{w.creation_date}[/#29B8DB]")
    print(f"[#23D18B]Expiration date[/#23D18B]:[#29B8DB]{w.expiration_date}[/#29B8DB]")
    print(f"[#23D18B]Name servers[/#23D18B]:[#29B8DB]{w.name_servers}[/#29B8DB]")
    print(f"[#23D18B]Status[/#23D18B]:[#29B8DB]{w.status}[/#29B8DB]")
    print(f"[#23D18B]Emails[/#23D18B]:[#29B8DB]{w.emails}[/#29B8DB]")
    print(f"[#23D18B]Dnssec[/#23D18B]:[#29B8DB]{w.dnssec}[/#29B8DB]")
    print(f"[#23D18B]Name[/#23D18B]:[#29B8DB]{w.name}[/#29B8DB]")
    print(f"[#23D18B]Org[/#23D18B]:[#29B8DB]{w.org}[/#29B8DB]")
    print(f"[#23D18B]Address[/#23D18B]:[#29B8DB]{w.address}[/#29B8DB]")
    print(f"[#23D18B]City[/#23D18B]:[#29B8DB]{w.city}[/#29B8DB]")
    print(f"[#23D18B]State[/#23D18B]:[#29B8DB]{w.state}[/#29B8DB]")
    print(f"[#23D18B]Zipcode[/#23D18B]:[#29B8DB]{w.zipcode}[/#29B8DB]")
    print(f"[#23D18B]Country[/#23D18B]:[#29B8DB]{w.country}[/#29B8DB]")
    print("─" * 50)

def get_ssl(target="127.0.0.1"):
    print("[#3B78FF]Geting SSL info...[/#3B78FF]")
    print("─" * 50)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.connect((target, 443))
            cert = s.getpeercert()
        print(cert)
    except:
        print('Error')
    print("─" * 50)

def get_info_by_ip(ip='127.0.0.1'):
    print("[#3B78FF]Scanning ip information...[/#3B78FF]")
    print("─" * 50)
    ip_1 = socket.gethostbyname(ip)
    try:
        response = requests.get(url=f'http://ip-api.com/json/{ip_1}').json()
        
        data = {
            'IP': response.get('query'),
            'Int prov': response.get('isp'),
            'Org': response.get('org'),
            'Country': response.get('country'),
            'Region Name': response.get('regionName'),
            'City': response.get('city'),
            'ZIP': response.get('zip'),
            'Lat': response.get('lat'),
            'Lon': response.get('lon'),
        }
        
        for k, v in data.items():
            print(f'[#23D18B]{k}[/#23D18B]: [#29B8DB]{v}[/#29B8DB]')
        print("─" * 50)
        
    except requests.exceptions.ConnectionError:
        print('[!] Please check your connection!')

target = input("Enter a remote host to scan: ")
try:
    ip = socket.gethostbyname(target)
    print("─" * 50)
    print("[#23D18B]Scanning Target: [/#23D18B]" + "[#29B8DB]" + target + "[/#29B8DB]")
    print("[#23D18B]Host ip: [/#23D18B]" + "[#29B8DB]" + ip + "[/#29B8DB]")
    print("[#23D18B]Scanning started at: [/#23D18B]" + "[#29B8DB]" + str(datetime.now()) + "[/#29B8DB]")
    print("─" * 50)
    get_info_by_ip(target)
    get_records(target)
    get_whois(target)
    get_ssl(target)

except:
    print("[#C50F1F]Hostname Could Not Be Resolved![/#C50F1F]")
    input()
print("="*50)
print("[#FEC42D]Ready![/#FEC42D]")
input("Press enter to quit...")
