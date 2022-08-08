import os
import sys
from xml import dom
from xmlrpc.client import boolean
from phishing import logger

from phishing.exception import PhishingException
from phishing.util.util import load_object

import pandas as pd
import string

# extract url data imports 

from urllib.parse import urlparse
from urllib.parse import parse_qs

# for tld
from tld import get_tld

import re 

import requests
import time

# spf
from urllib.request import url2pathname
import dns.resolver

# asn ip 
from cymruwhois import Client
import socket

# domain information
import whois
from datetime import date


# google index

from bs4 import BeautifulSoup

# check url shortening
import urllib.request











class PhisingUrlData:

    def __init__(self,check_url:string):
        try:
            self.check_url = check_url
            
        except Exception as e:
            raise PhishingException(e, sys) from e

    def get_phishing_input_data_frame(self):

        try:
            phishing_input_dict = self.get_url_extract_data_as_dict()
            logger.logging.info(phishing_input_dict)
            return pd.DataFrame([phishing_input_dict])
        except Exception as e:
            raise PhishingException(e, sys) from e

    def get_url_extract_data_as_dict(self):
        try:


            url = self.check_url
            url_info = urlparse(url)
            domain = url_info.netloc
            paths = url_info.path
            params = url_info.query

            input_data ={ **self.__get_url_whole_extract_data_as_dict(url =url ) , **self.__get_domain_extract_data_as_dict(domain=domain) , **self.__get_extract_paths_data_as_dict(path=paths) ,
                 **self.__get_extract_file_data_as_dict(path=paths) , **self.__get_extract_params_data_as_dict(params=params) , **self.__get_extract_extra_data_as_dict(url = url, domain= domain)
            }

            # input_data = {k:[v] for k,v in input_data.items()}
            print(len(input_data))    
            return input_data
        except Exception as e:
            raise PhishingException(e, sys)

    ## whole url related
    def __get_url_whole_extract_data_as_dict(self,url:string):
        try:
            
            isHasEmail = re.match(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", url)
            url_data = {}
            url_data["qty_dot_url"] = url.count(".")
            url_data["qty_hyphen_url"] = url.count("-")
            url_data["qty_underline_url"] = url.count("_")
            url_data["qty_slash_url"] = url.count("/")
            url_data["qty_questionmark_url"] = url.count("?")
            url_data["qty_equal_url"] = url.count("=")
            url_data["qty_at_url"] = url.count("@")
            url_data["qty_and_url"] = url.count("&")
            url_data["qty_exclamation_url"] = url.count("!")
            url_data["qty_space_url"] = url.count(" ")
            url_data["qty_tilde_url"] = url.count("~")
            url_data["qty_comma_url"] = url.count(",")
            url_data["qty_plus_url"] = url.count("+")
            url_data["qty_asterisk_url"] = url.count("*")
            url_data["qty_hashtag_url"] = url.count("#")
            url_data["qty_dollar_url"] = url.count("$")
            url_data["qty_percent_url"] = url.count("%")
            url_data["qty_tld_url"] = len(get_tld(url))
            url_data["length_url"] = len(url)
            # ////////////
            url_data["email_in_url"] = 1 if isHasEmail else 0

            return url_data
        except Exception as e:
            raise PhishingException(e,sys)     


    ## domain extract related
    def __get_domain_extract_data_as_dict(self,domain:string):
        try:
            
            # domain = url_info.netloc

            domain_url_data = {}

            isOnlyIP = re.match("[0-9.]",domain)
            vowels = "".join(re.findall('([aeiou]*)', domain, flags=re.I))

            domain_url_data["qty_dot_domain"] = domain.count(".")
            domain_url_data["qty_hyphen_domain"] = domain.count("-")
            domain_url_data["qty_underline_domain"] = domain.count("_")
            domain_url_data["qty_slash_domain"] = domain.count("/")
            domain_url_data["qty_questionmark_domain"] = domain.count("?")
            domain_url_data["qty_equal_domain"] = domain.count("=")
            domain_url_data["qty_at_domain"] = domain.count("@")
            domain_url_data["qty_and_domain"] = domain.count("&")
            domain_url_data["qty_exclamation_domain"] = domain.count("!")
            domain_url_data["qty_space_domain"] = domain.count(" ")
            domain_url_data["qty_tilde_domain"] = domain.count("~")
            domain_url_data["qty_comma_domain"] = domain.count(",")
            domain_url_data["qty_plus_domain"] = domain.count("+")
            domain_url_data["qty_asterisk_domain"] = domain.count("*")
            domain_url_data["qty_hashtag_domain"] = domain.count("#")
            domain_url_data["qty_dollar_domain"] = domain.count("$")
            domain_url_data["qty_percent_domain"] = domain.count("%")
            domain_url_data["qty_vowels_domain"] = len(vowels)
            domain_url_data["domain_length"] = len(domain)
            domain_url_data["domain_in_ip"] = 1 if isOnlyIP else 0
            domain_url_data["server_client_domain"] = 0


            return domain_url_data

            
        except Exception as e:
            raise PhishingException(e,sys)  


     ## path extract related
    def __get_extract_paths_data_as_dict(self,path:string):
        try:
            directory_url_data = {}
            
            # paths = re.match(r"(.*/)",url_info.path)
            paths = re.match(r"(.*/)",path)

            if True:
                directory = paths.group()  if paths  else ""
                print("dir",directory,path)
                

                directory_url_data["qty_dot_directory"] =  directory.count(".") if paths  else -1
                directory_url_data["qty_hyphen_directory"] = directory.count("-") if paths  else -1
                directory_url_data["qty_underline_directory"] = directory.count("_") if paths  else -1
                directory_url_data["qty_slash_directory"] = directory.count("/") if paths  else -1
                directory_url_data["qty_questionmark_directory"] = directory.count("?") if paths  else -1
                directory_url_data["qty_equal_directory"] = directory.count("=") if paths  else -1
                directory_url_data["qty_at_directory"] = directory.count("@") if paths  else -1
                directory_url_data["qty_and_directory"] = directory.count("&") if paths  else -1
                directory_url_data["qty_exclamation_directory"] = directory.count("!") if paths  else -1
                directory_url_data["qty_space_directory"] = directory.count(" ") if paths  else -1
                directory_url_data["qty_tilde_directory"] = directory.count("~") if paths  else -1
                directory_url_data["qty_comma_directory"] = directory.count(",") if paths  else -1
                directory_url_data["qty_plus_directory"] = directory.count("+") if paths  else -1
                directory_url_data["qty_asterisk_directory"] = directory.count("*") if paths  else -1
                directory_url_data["qty_hashtag_directory"] = directory.count("#") if paths  else -1
                directory_url_data["qty_dollar_directory"] = directory.count("$") if paths  else -1
                directory_url_data["qty_percent_directory"] = directory.count("%") if paths  else -1
                directory_url_data["directory_length"] = len(directory) if paths  else -1

            return directory_url_data
            
        except Exception as e:
            raise PhishingException(e,sys) 


     ## file extract related
    def __get_extract_file_data_as_dict(self,path:string):
        try:
            file_url_data = {}
            # paths = re.match(r"/.*[/](.*[.].*)",url_info.path)
            paths = re.match(r"/.*[/](.*[.].*)",path)
            if True:  
                file = paths.groups()[0] if paths  else ""
                print("file",file,path)
                
                file_url_data["qty_dot_file"] = file.count(".") if paths  else -1
                file_url_data["qty_hyphen_file"] = file.count("-") if paths  else -1
                file_url_data["qty_underline_file"] = file.count("_") if paths  else -1
                file_url_data["qty_slash_file"] = file.count("/") if paths  else -1
                file_url_data["qty_questionmark_file"] = file.count("?") if paths  else -1
                file_url_data["qty_equal_file"] = file.count("=") if paths  else -1
                file_url_data["qty_at_file"] = file.count("@") if paths  else -1
                file_url_data["qty_and_file"] = file.count("&") if paths  else -1
                file_url_data["qty_exclamation_file"] = file.count("!") if paths  else -1
                file_url_data["qty_space_file"] = file.count(" ") if paths  else -1
                file_url_data["qty_tilde_file"] = file.count("~") if paths  else -1
                file_url_data["qty_comma_file"] = file.count(",") if paths  else -1
                file_url_data["qty_plus_file"] = file.count("+") if paths  else -1
                file_url_data["qty_asterisk_file"] = file.count("*") if paths  else -1
                file_url_data["qty_hashtag_file"] = file.count("#") if paths  else -1
                file_url_data["qty_dollar_file"] = file.count("$") if paths  else -1
                file_url_data["qty_percent_file"] = file.count("%") if paths  else -1
                file_url_data["file_length"] = len(file)

            return file_url_data    
            
        except Exception as e:
            raise PhishingException(e,sys)


     ## params extract related
    def __get_extract_params_data_as_dict(self,params:string):
        try:
            # params = url_info.query
            
            params_url_data = {}

            params_url_data["qty_dot_params"] = params.count(".") if len(params) > 0 else -1
            params_url_data["qty_hyphen_params"] = params.count("-") if len(params) > 0 else -1
            params_url_data["qty_underline_params"] = params.count("_") if len(params) > 0 else -1
            params_url_data["qty_slash_params"] = params.count("/")  if len(params) > 0 else -1
            params_url_data["qty_questionmark_params"] = params.count("?")  if len(params) > 0 else -1
            params_url_data["qty_equal_params"] = params.count("=")  if len(params) > 0 else -1
            params_url_data["qty_at_params"] = params.count("@")  if len(params) > 0 else -1
            params_url_data["qty_and_params"] = params.count("&")  if len(params) > 0 else -1
            params_url_data["qty_exclamation_params"] = params.count("!")  if len(params) > 0 else -1
            params_url_data["qty_space_params"] = params.count(" ") if len(params) > 0 else -1
            params_url_data["qty_tilde_params"] = params.count("~") if len(params) > 0 else -1
            params_url_data["qty_comma_params"] = params.count(",") if len(params) > 0 else -1
            params_url_data["qty_plus_params"] = params.count("+") if len(params) > 0 else -1
            params_url_data["qty_asterisk_params"] = params.count("*") if len(params) > 0 else -1
            params_url_data["qty_hashtag_params"] = params.count("#") if len(params) > 0 else -1
            params_url_data["qty_dollar_params"] = params.count("$") if len(params) > 0 else -1
            params_url_data["qty_percent_params"] = params.count("%") if len(params) > 0 else -1
            params_url_data["params_length"] = len(params) if len(params) > 0 else -1
            # tld present parms 
            params_url_data["tld_present_params"] = -1
            params_url_data["qty_params"] = len(parse_qs(params))  if len(params) > 0 else -1

            return params_url_data    
            
        except Exception as e:
            raise PhishingException(e,sys) 



     ## extract extra data from url related
    def __get_extract_extra_data_as_dict(self,url:string,domain:string):
        try:
            # params = url_info.query
            
            extra_url_data = {}

            extra_url_data["time_response"] = self.__get_time_response(url=url)
            extra_url_data["domain_spf"] = self.__get_domain_spf(domain=domain)
            extra_url_data["asn_ip"] = self.__get_asn_ip(domain=domain)
            extra_url_data["time_domain_activation"] = self.__get_time_domain_activation(domain=domain)
            extra_url_data["time_domain_expiration"] = self.__get_time_domain_expiration(domain=domain)
            extra_url_data["qty_ip_resolved"] = self.__get_qty_ip_resolved(domain=domain)
            extra_url_data["qty_nameservers"] = self.__get_qty_nameservers(domain=domain)
            extra_url_data["qty_mx_servers"] = self.__get_qty_mx_servers(domain=domain)
            
            extra_url_data["ttl_hostname"] = self.__get_ttl_hostname(domain=domain)

            extra_url_data["tls_ssl_certificate"] = self.__get_tls_ssl_certificate(url=url)
            extra_url_data["qty_redirects"] = self.__get_qty_redirects(url=url)
            extra_url_data["url_google_index"] = self.__get_url_google_index(url=url)
            extra_url_data["domain_google_index"] = self.__get_url_google_index(url=domain)
            extra_url_data["url_shortened"] = self.__get_is_url_shortened(url=url)
    

            return extra_url_data    
            
        except Exception as e:
            raise PhishingException(e,sys) 


    def __get_time_response(self,url:string)-> float:
        try:
            start = time.time()
            r = requests.get(url)
            roundtrip = time.time() - start
            return round(roundtrip,4)
        except Exception as e:
            return -1


    def __get_domain_spf(self,domain:string)-> int:
        try:
            type = [
        "A",
        "AAAA",
        "MX",
        "TXT",
    ]

            isSPF_domain = 0
            for record in type:
                    try:
                        result = dns.resolver.resolve(domain, record)
                        for val in result:
                            if "spf" in val.to_text():
                                print("[+] SPF Record: ", val.to_text())
                                isSPF_domain = 1
                            else:
                                print(f"[+] {record} Record :", val.to_text())
                    except:
                        print(f"[.] Record not found {record} in domain '{domain}'.")

            return isSPF_domain            
        except Exception as e:
            return -1


    def __get_asn_ip(self,domain:string)-> int:
        try:
            ip = socket.gethostbyname(domain)
            c=Client()
            asn_ip = -1
            for r in c.lookupmany([ip]):
                asn_ip = r.asn
            return asn_ip    
        except Exception as e:
            return -1  


    def __get_time_domain_activation(self,domain:string)-> int:
        try:
            w = whois.whois(domain) 
            d1 = date.today()
            try:
                d0 = w.creation_date.date()
            except Exception as e:
                d0 = w.creation_date[0].date()
            time_domain_activation = (d1 - d0).days
            return time_domain_activation
        except Exception as e:
            return -1  

    def __get_time_domain_expiration(self,domain:string)-> int:
         try:
            w = whois.whois(domain) 
            d0 = date.today()
            try:
                d1 = w.expiration_date.date()
            except Exception as e:
                d1 = w.expiration_date[0].date()
            time_domain_activation = (d1 - d0).days
            return time_domain_activation
         except Exception as e:
            return -1 

    def __get_qty_ip_resolved(self,domain:string)-> int:
        try:
            
            return len(self.resolve_host_ip(domain))
        except Exception as e:
            return -1 


    def resolve_host_ip(self,host):
        ret = set()
        try:
            r = socket.getaddrinfo(host, None)
            for i in r:
                if ':' not in i[4][0]:
                    ret.add(i[4][0])
        except Exception as e:
            pass
        return list(ret)   


    def __get_qty_nameservers(self,domain:string)-> int:
        try:
            w = whois.whois(domain) 
            return len(w.name_servers)
        except Exception as e:
            return -1
            #raise PhishingException(e,sys)  


    def __get_qty_mx_servers(self,domain:string)-> int:
        try:
            
            return len(dns.resolver.resolve(domain, 'MX'))
        except Exception as e:
            # raise PhishingException(e,sys)  
            return -1


    # not found suitable 
    def __get_ttl_hostname(self,domain:string)-> int:
        try:
            
            return -1
        except Exception as e:
            raise PhishingException(e,sys)     


    def __get_tls_ssl_certificate(self,url:string)-> int:
        try:
            tls_ssl_certificate = 0
            if "https://" in url:
                tls_ssl_certificate = 1
            return tls_ssl_certificate
        except Exception as e:
            raise PhishingException(e,sys)   


    def __get_qty_redirects(self,url:string)-> int:
        try:
            response = requests.get(url)
            qty_redirects = len(response.history)
            
            return qty_redirects
        except Exception as e:
            raise PhishingException(e,sys)


    def __get_url_google_index(self,url:string)-> int:
        try:
            url_google_index = 0
            google = "https://www.google.com/search?q=site:" + url + "&hl=en"
            response = requests.get(google, cookies={"CONSENT": "YES+1"})
            soup = BeautifulSoup(response.content, "html.parser")
            not_indexed = re.compile("did not match any documents")

            if soup(text=not_indexed):
                url_google_index = 0
            else:
                url_google_index = 1

            return url_google_index  
        except Exception as e:
            return -1


    def __get_is_url_shortened(self,url:string)-> int:
        try:
            wp = urllib.request.urlopen(url)

            # response_code will be 302 for redirects
            response_code = wp.getcode()

            if response_code == 302 and len(url) < 51:
                url_shortened = 1
            else:
                url_shortened = 0 

            return url_shortened    
        except Exception as e:
            return -1                                                                         








class HousingPredictor:

    def __init__(self, model_dir: str):
        try:
            self.model_dir = model_dir
        except Exception as e:
            raise PhishingException(e, sys) from e

    def get_latest_model_path(self):
        try:
            folder_name = list(map(int, os.listdir(self.model_dir)))
            latest_model_dir = os.path.join(self.model_dir, f"{max(folder_name)}")
            file_name = os.listdir(latest_model_dir)[0]
            latest_model_path = os.path.join(latest_model_dir, file_name)
            return latest_model_path
        except Exception as e:
            raise PhishingException(e, sys) from e

    def predict(self, X):
        try:
            model_path = self.get_latest_model_path()
            model = load_object(file_path=model_path) 
            
            median_house_value = model.predict(X)
            logger.logging.info(f"predict result {median_house_value}")
            return median_house_value
        except Exception as e:
            raise PhishingException(e, sys) from e