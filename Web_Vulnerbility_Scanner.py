## Web Vulnerbility Scanner
from scapy.all import ARP, Ether, srp
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

def menu():
    print("Choose your Options")
    #time.sleep(1)
    print()

    choice = input("""
                      1:Port Scanner
                      2:XSS Scanner
                      3:SQL Injection Scanner
                      4:Quit
                      

                      Please enter your choice: """)

    if choice == "1":
        portscanner()
    elif choice == "2":
        xssscanner()
    elif choice == "3":
        sqlscanner()

    elif choice=="4":
        sys.exit
    else:
        print("You must only select either 1,2,3,or 4.")
        print("Please try again")
        menu()
def portscanner():

	target_ip = input()
	arp = ARP(pdst=target_ip)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether/arp
	result = srp(packet, timeout=3, verbose=0)[0]
	clients = []
	for sent, received in result:
    
    	clients.append({'ip': received.psrc, 'mac': received.hwsrc})

	print("Available devices in the network:")
	print("IP" + " "*18+"MAC")
	for client in clients:
    	print("{:16}    {}".format(client['ip'], client['mac']))

def xssscanner():
		url = input()
	    soup = bs(requests.get(url).content, "html.parser")
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
        	requests.post(target_url, data=data)
        else:
        	requests.get(target_url, params=data)

        forms = get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        js_script = "<Script>alert('hi')</scripT>"
        is_vulnerable = False
        for form in forms:
                form_details = get_form_details(form)
       			content = submit_form(form_details, url, js_script).content.decode()
       		 	if js_script in content:
           			 print(f"[+] XSS Detected on {url}")
            	 	print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
        return is_vulnerable
def sqlscanner():
	url = input()
	s = requests.Session()
	s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
	soup = bs(s.get(url).content, "html.parser")
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

    	def is_vulnerable(response)
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
            return True
    
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
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
