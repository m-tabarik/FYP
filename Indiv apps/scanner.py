Target_url= input("Enter URL to SCAN")


import requests
import argparse
from urllib.parse import urlparse
import socket

import http.client
import re

import ssl
import sys
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import os
from bs4 import BeautifulSoup as bs
import colorama


import utils
from constants import DEFAULT_URL_SCHEME, EVAL_WARN





def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error: {e}")
        return None

# Example usage
domain_name = Target_url
ip_address = get_ip_address(domain_name)

def scan_ports(target, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((target, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports

# Example usage
target_host = ip_address # Replace this with the target IP address or domain name
start_ports = "79"
end_ports = "81"
start_port = int(start_ports)
end_port = int(end_ports)
open_ports = scan_ports(target_host, start_port, end_port)

if open_ports:
    print("Open ports:")
    for port in open_ports:
        print(port)
else:
    print("No open ports found.")

# Mask the user agent so it doesn't show as python and get blocked, set global for request that needs to allow for redirects
# Get function to swap the user agent
def get(websiteToScan):
    global user_agent
    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',
    }
    return requests.get(websiteToScan, allow_redirects=False, headers=user_agent)

# Function to detect WordPress
def detect_wordpress(websiteToScan):
    wp_paths = ['/wp-login.php', '/wp-admin', '/wp-admin/upgrade.php', '/readme.html']
    
    for path in wp_paths:
        wp_check = get(websiteToScan + path)
        if wp_check.status_code == 200 and "404" not in wp_check.text:
            print("[!] Detected: WordPress at " + websiteToScan + path)
        else:
            print(" |  Not Detected: WordPress at " + websiteToScan + path)

# Function to detect Joomla
def detect_joomla(websiteToScan):
    joomla_paths = ['/administrator/', '/readme.txt']
    
    for path in joomla_paths:
        joomla_check = get(websiteToScan + path)
        if joomla_check.status_code == 200 and "404" not in joomla_check.text:
            print("[!] Detected: Joomla at " + websiteToScan + path)
        else:
            print(" |  Not Detected: Joomla at " + websiteToScan + path)

# Function to detect Magento
def detect_magento(websiteToScan):
    magento_paths = ['/index.php/admin/', '/RELEASE_NOTES.txt', '/js/mage/cookies.js', '/skin/frontend/default/default/css/styles.css', '/errors/design.xml']
    
    for path in magento_paths:
        magento_check = get(websiteToScan + path)
        if magento_check.status_code == 200 and "404" not in magento_check.text:
            print("[!] Detected: Magento at " + websiteToScan + path)
        else:
            print(" |  Not Detected: Magento at " + websiteToScan + path)

# Function to detect Drupal
def detect_drupal(websiteToScan):
    drupal_paths = ['/readme.txt', '/core/COPYRIGHT.txt', '/modules/README.txt']
    
    for path in drupal_paths:
        drupal_check = get(websiteToScan + path)
        if drupal_check.status_code == 200 and "404" not in drupal_check.text:
            print("[!] Detected: Drupal at " + websiteToScan + path)
        else:
            print(" |  Not Detected: Drupal at " + websiteToScan + path)

# Function to detect phpMyAdmin
def detect_phpmyadmin(websiteToScan):
    phpmyadmin_paths = ['/index.php', '/config.inc.php']
    
    for path in phpmyadmin_paths:
        phpmyadmin_check = get(websiteToScan + path)
        if phpmyadmin_check.status_code == 200 and "404" not in phpmyadmin_check.text:
            print("[!] Detected: phpMyAdmin at " + websiteToScan + path)
        else:
            print(" |  Not Detected: phpMyAdmin at " + websiteToScan + path)

# Begin scan
def scan():
    # Check to see if the site argument was specified
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--site", help="Use this option to specify the domain or IP to scan.")
    args = parser.parse_args()
    if args.site is None:
        # Get the input from the user
        print("Please enter the site or IP you would like to scan below.")
        print("Examples - www.site.com, https://store.org/magento, 192.168.1.50")
        websiteToScan = Target_url
    else:
        websiteToScan = args.site

    # Check the input for HTTP or HTTPS and then remove it, if nothing is found assume HTTP
    if websiteToScan.startswith('http://'):
        proto = 'http://'
        websiteToScan = websiteToScan[7:]
    elif websiteToScan.startswith('https://'):
        proto = 'https://'
        websiteToScan = websiteToScan[8:]
    else:
        proto = 'http://'

    # Check the input for an ending / and remove it if found
    if websiteToScan.endswith('/'):
        websiteToScan = websiteToScan.strip('/')

    # Combine the protocol and site
    websiteToScan = proto + websiteToScan

    # Check to see if the site is online
    print("[+] Checking to see if the site is online...")

    try:
        onlineCheck = get(websiteToScan)
    except requests.exceptions.ConnectionError as ex:
        print("[!] " + websiteToScan + " appears to be offline.")
    else:
        if onlineCheck.status_code == 200 or onlineCheck.status_code == 301 or onlineCheck.status_code == 302:
            print(" |  " + websiteToScan + " appears to be online.")
            print("Beginning scan...")

            detect_wordpress(websiteToScan)
            detect_joomla(websiteToScan)
            detect_magento(websiteToScan)
            detect_drupal(websiteToScan)
            detect_phpmyadmin(websiteToScan)

        else:
            print("[!] " + websiteToScan + " appears to be online but returned a " + str(onlineCheck.status_code) + " error.")
            exit()

        print("[+] Attempting to get the HTTP headers...")
        # Pretty print( the headers - courtesy of Jimmy
        for header in onlineCheck.headers:
            try:
                print(" | " + header + " : " + onlineCheck.headers[header])
            except Exception as ex:
                print("[!] Error: " + str(ex))

        print("Scan is now complete!")

# Call the scan function
scan()



#SUBDOMAINS


# function for scanning subdomains
def domain_scanner(domain_name,sub_domnames):
	print('----URL after scanning subdomains----')
	
	# loop for getting URL's
	for subdomain in sub_domnames:
	
		# making url by putting subdomain one by one
		url = f"https://{subdomain}.{domain_name}"
		
		# using try catch block to avoid crash of the
		# program
		try:
			# sending get request to the url
			requests.get(url)
			
			# if after putting subdomain one by one url 
			# is valid then printing the url
			print(f'[+] {url}')
			
			# if url is invalid then pass it
		except requests.ConnectionError:
			pass

# main function
if __name__ == '__main__':

	# inputting the domain name
	dom_name = Target_url
	# opening the subdomain text file
	with open('subdomain_names.txt','r') as file:
	
		# reading the file
		name = file.read()
		
		# using splitlines() function storing the list
		# of splitted strings
		sub_dom = name.splitlines()
		
	# calling the function for scanning the subdomains
	# and getting the url
	domain_scanner(dom_name,sub_dom)
	




#BROKEN ACCESS CONTORL

def fuzz_web_application(target_url, file_path, allowed_status_codes):
    banner = r"""
                       
    """

    headings = ["URI", "Status Code"]
    col_widths = [max(len(heading), 8) for heading in headings]
    uri_col_width = col_widths[0]
    status_code_width = 10  # Fixed width for the status code column

    print(banner)
    print("\n")
    print("{:<{}}  {:>{}}".format(headings[0], uri_col_width, headings[1], status_code_width))
    print("-" * (sum(col_widths) + status_code_width + 2))

    with open(file_path, 'r') as file:
        for line in file:
            entry = line.strip()
            url = f"http://{target_url}/{entry}"  # Construct the URL with the directory path

            try:
                response = requests.get(url, stream=True)
                uri = urlparse(url).path  # Extract the URI from the URL
                status_code = str(response.status_code)

                if status_code in allowed_status_codes:
                    print("{:<{}}  {:>{}}".format(uri, uri_col_width, status_code, status_code_width))
            except requests.exceptions.RequestException:
                pass

    print("-" * (sum(col_widths) + status_code_width + 2))

if __name__ == '__main__':
    target_url = Target_url
    file_path = "bacdirectories.txt"
    allowed_status_codes = '200'

    if not file_path.endswith('.txt'):
        print("Error: The input file must be a text file (.txt)")
        exit(1)

    fuzz_web_application(target_url, file_path, allowed_status_codes)















###SQL 
    


    
# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break


if __name__ == "__main__":
    url = "http://testphp.vulnweb.com/artists.php?artist=1"
    scan_sql_injection(url)









#   XSS
    

    
os.system("clear")
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        return requests.get(target_url, params=data)

xss_payloads=['<script>alert(2)</script>']
def scan_xss(url):
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if payload in response.content.decode():
                print(colorama.Fore.RED + f"[!] XSS Detected on {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                pprint(form_details)
                break

if __name__ == "__main__":
    colorama.init()
    url = input("Enter the target URL: ")
    scan_xss(url)
    colorama.deinit()



