from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import tldextract
import requests
import re
from urllib.parse import urlparse, parse_qs
import dns.resolver
import whois
from datetime import datetime
import pickle
import numpy as np
import os
from django.conf import settings
from .models import UrlMetrics  


# Function to count specific characters in a string
def count_characters(s, chars):
    return {f"qty_{char}_url": s.count(char) for char in chars}

# Function to get domain information
def get_domain_info(url):
    ext = tldextract.extract(url)
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    suffix = ext.suffix
    subdomain = ext.subdomain
    if not subdomain:
        subdomain = None  # Set to None if no subdomain
    return domain, suffix, subdomain

# Function to get the length of top-level domain (TLD)
def get_tld_length(url):
    ext = tldextract.extract(url)
    return len(ext.suffix)

# Function to check if a URL has a specific keyword
def has_keyword(url, keywords):
    return any(keyword in url for keyword in keywords)

# Function to fetch DNS information
def fetch_dns_info(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [answer.to_text() for answer in answers]
    except:
        ip_addresses = []

    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [answer.to_text() for answer in ns_answers]
    except:
        nameservers = []

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_servers = [answer.to_text() for answer in mx_answers]
    except:
        mx_servers = []

    return ip_addresses, nameservers, mx_servers

# Function to get domain activation time
def get_time_domain_activation(domain):
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):  # sometimes it's a list
            creation_date = creation_date[0]
        time_domain_activation = (datetime.now() - creation_date).days
    except:
        time_domain_activation = -1
    return time_domain_activation

# Function to get domain expiration time
def get_time_domain_expiration(domain):
    try:
        whois_info = whois.whois(domain)
        expiration_date = whois_info.expiration_date
        if isinstance(expiration_date, list):  # sometimes it's a list
            expiration_date = expiration_date[0]
        time_domain_expiration = (expiration_date - datetime.now()).days
    except:
        time_domain_expiration = -1
    return time_domain_expiration

# Function to fetch external features
def fetch_external_features(url, domain):
    external_features = {}

    # Check if email is in URL
    external_features["email_in_url"] = int("@" in url)

    # Check response time
    try:
        response = requests.get(url, timeout=5)
        external_features["time_response"] = response.elapsed.total_seconds() * 1000
    except requests.exceptions.RequestException:
        external_features["time_response"] = -1

    # Check SPF record
    try:
        spf_answers = dns.resolver.resolve(domain, 'TXT')
        spf_records = [answer.to_text() for answer in spf_answers if 'v=spf1' in answer.to_text()]
        external_features["domain_spf"] = int(len(spf_records) > 0)
    except:
        external_features["domain_spf"] = 0

    # Fetch DNS info
    ip_addresses, nameservers, mx_servers = fetch_dns_info(domain)
    external_features["asn_ip"] = len(ip_addresses)
    external_features["qty_ip_resolved"] = len(ip_addresses)
    external_features["qty_nameservers"] = len(nameservers)
    external_features["qty_mx_servers"] = len(mx_servers)

    # Time-to-live (TTL) value
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ttl_values = [answer.ttl for answer in answers]
        external_features["ttl_hostname"] = min(ttl_values) if ttl_values else -1
    except:
        external_features["ttl_hostname"] = -1

    # Check TLS/SSL certificate
    try:
        response = requests.get("https://" + domain, timeout=5)
        external_features["tls_ssl_certificate"] = int(response.url.startswith("https"))
    except requests.exceptions.RequestException:
        external_features["tls_ssl_certificate"] = 0

    # Number of redirects
    try:
        response = requests.get(url, timeout=5)
        external_features["qty_redirects"] = len(response.history)
    except requests.exceptions.RequestException:
        external_features["qty_redirects"] = -1

    # Check if URL and domain are indexed by Google
    google_search_url = f"https://www.google.com/search?q=site:{url}"
    try:
        response = requests.get(google_search_url, timeout=5)
        external_features["url_google_index"] = int("did not match any documents" not in response.text)
    except requests.exceptions.RequestException:
        external_features["url_google_index"] = 0

    google_search_domain = f"https://www.google.com/search?q=site:{domain}"
    try:
        response = requests.get(google_search_domain, timeout=5)
        external_features["domain_google_index"] = int("did not match any documents" not in response.text)
    except requests.exceptions.RequestException:
        external_features["domain_google_index"] = 0

    # Check if URL is shortened
    shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
    external_features["url_shortened"] = int(any(shortened_domain in url for shortened_domain in shortened_domains))

    # Domain activation and expiration times
    external_features["time_domain_activation"] = get_time_domain_activation(domain)
    external_features["time_domain_expiration"] = get_time_domain_expiration(domain)
    print("time activation: ",external_features['time_domain_activation'])

    return external_features

# Function to extract features from a URL
def extract_features(url):
    features = {}

    # URL parsing
    parsed_url = urlparse(url)
    domain, suffix, subdomain = get_domain_info(url)
    path = parsed_url.path
    params = parsed_url.query
    fragment = parsed_url.fragment

    # Characters to count
    url_chars = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
    domain_chars = url_chars
    directory_chars = url_chars
    file_chars = url_chars
    params_chars = url_chars

    # URL-based features
    features.update(count_characters(url, url_chars))
    features['length_url'] = len(url)
    features['qty_tld_url'] = get_tld_length(url)

    # Domain-based features
    features.update({f'qty_{char}_domain': domain.count(char) for char in domain_chars})
    features['qty_vowels_domain'] = sum(map(domain.lower().count, "aeiou"))
    features['domain_length'] = len(domain)
    features['domain_in_ip'] = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)))
    features['server_client_domain'] = int(has_keyword(domain, ["server", "client"]))

    # Directory-based features
    directories = path.split('/')
    features.update({f'qty_{char}_directory': path.count(char) for char in directory_chars})
    features['directory_length'] = len(path)

    # File-based features
    file_name = directories[-1] if '.' in directories[-1] else ""
    features.update({f'qty_{char}_file': file_name.count(char) for char in file_chars})
    features['file_length'] = len(file_name)

    # Parameters-based features
    params_values = parse_qs(params)
    params_string = '&'.join([f"{k}={v[0]}" for k, v in params_values.items()])
    features.update({f'qty_{char}_params': params_string.count(char) for char in params_chars})
    features['params_length'] = len(params_string)
    features['qty_params'] = len(params_values)

    # Check if TLD is present in params
    features['tld_present_params'] = int(any(suffix in v[0] for v in params_values.values()))

    # External features
    external_features = fetch_external_features(url, domain)
    features.update(external_features)
    print(features)
    return features
@csrf_exempt 
def feedback(request):
    if request.method == 'POST':
        website_url = request.POST.get('websiteUrl')
        feedback_type = request.POST.get('feedbackType')
        if website_url and feedback_type:
            data = extract_features(website_url)
            try:
                # Create a new instance of UrlMetrics
                url_metrics = UrlMetrics(
                
                # Set the fields dynamically
                qty_dot_url=data.get('qty_._url', 0),
                qty_hyphen_url=data.get('qty_-_url', 0),
                qty_underline_url=data.get('qty___url', 0),
                qty_slash_url=data.get('qty_/_url', 0),
                qty_questionmark_url=data.get('qty_?_url', 0),
                qty_equal_url=data.get('qty_=_url', 0),
                qty_at_url=data.get('qty_@_url', 0),
                qty_and_url=data.get('qty_&_url', 0),
                qty_exclamation_url=data.get('qty_!_url', 0),
                qty_space_url=data.get('qty_ _url', 0),
                qty_tilde_url=data.get('qty_~_url', 0),
                qty_comma_url=data.get('qty_,_url', 0),
                qty_plus_url=data.get('qty_+_url', 0),
                qty_asterisk_url=data.get('qty_*_url', 0),
                qty_hashtag_url=data.get('qty_#_url', 0),
                qty_dollar_url=data.get('qty_$_url', 0),
                qty_percent_url=data.get('qty_%_url', 0),
                qty_tld_url=data.get('qty_tld_url', 0),
                length_url=data.get('length_url', 0),
                qty_dot_domain=data.get('qty_._domain', 0),
                qty_hyphen_domain=data.get('qty_-_domain', 0),
                qty_underline_domain=data.get('qty___domain', 0),
                qty_slash_domain=data.get('qty_/_domain', 0),
                qty_questionmark_domain=data.get('qty_?_domain', 0),
                qty_equal_domain=data.get('qty_=_domain', 0),
                qty_at_domain=data.get('qty_@_domain', 0),
                qty_and_domain=data.get('qty_&_domain', 0),
                qty_exclamation_domain=data.get('qty_!_domain', 0),
                qty_space_domain=data.get('qty_ _domain', 0),
                qty_tilde_domain=data.get('qty_~_domain', 0),
                qty_comma_domain=data.get('qty_,_domain', 0),
                qty_plus_domain=data.get('qty_+_domain', 0),
                qty_asterisk_domain=data.get('qty_*_domain', 0),
                qty_hashtag_domain=data.get('qty_#_domain', 0),
                qty_dollar_domain=data.get('qty_$_domain', 0),
                qty_percent_domain=data.get('qty_%_domain', 0),
                qty_vowels_domain=data.get('qty_vowels_domain', 0),
                domain_length=data.get('domain_length', 0),
                domain_in_ip=data.get('domain_in_ip', 0),
                server_client_domain=data.get('server_client_domain', 0),
                qty_dot_directory=data.get('qty_._directory', 0),
                qty_hyphen_directory=data.get('qty_-_directory', 0),
                qty_underline_directory=data.get('qty___directory', 0),
                qty_slash_directory=data.get('qty_/_directory', 0),
                qty_questionmark_directory=data.get('qty_?_directory', 0),
                qty_equal_directory=data.get('qty_=_directory', 0),
                qty_at_directory=data.get('qty_@_directory', 0),
                qty_and_directory=data.get('qty_&_directory', 0),
                qty_exclamation_directory=data.get('qty_!_directory', 0),
                qty_space_directory=data.get('qty_ _directory', 0),
                qty_tilde_directory=data.get('qty_~_directory', 0),
                qty_comma_directory=data.get('qty_,_directory', 0),
                qty_plus_directory=data.get('qty_+_directory', 0),
                qty_asterisk_directory=data.get('qty_*_directory', 0),
                qty_hashtag_directory=data.get('qty_#_directory', 0),
                qty_dollar_directory=data.get('qty_$_directory', 0),
                qty_percent_directory=data.get('qty_%_directory', 0),
                directory_length=data.get('directory_length', 0),
                qty_dot_file=data.get('qty_._file', 0),
                qty_hyphen_file=data.get('qty_-_file', 0),
                qty_underline_file=data.get('qty___file', 0),
                qty_slash_file=data.get('qty_/_file', 0),
                qty_questionmark_file=data.get('qty_?_file', 0),
                qty_equal_file=data.get('qty_=_file', 0),
                qty_at_file=data.get('qty_@_file', 0),
                qty_and_file=data.get('qty_&_file', 0),
                qty_exclamation_file=data.get('qty_!_file', 0),
                qty_space_file=data.get('qty_ _file', 0),
                qty_tilde_file=data.get('qty_~_file', 0),
                qty_comma_file=data.get('qty_,_file', 0),
                qty_plus_file=data.get('qty_+_file', 0),
                qty_asterisk_file=data.get('qty_*_file', 0),
                qty_hashtag_file=data.get('qty_#_file', 0),
                qty_dollar_file=data.get('qty_$_file', 0),
                qty_percent_file=data.get('qty_%_file', 0),
                file_length=data.get('file_length', 0),
                qty_dot_params=data.get('qty_._params', 0),
                qty_hyphen_params=data.get('qty_-_params', 0),
                qty_underline_params=data.get('qty___params', 0),
                qty_slash_params=data.get('qty_/_params', 0),
                qty_questionmark_params=data.get('qty_?_params', 0),
                qty_equal_params=data.get('qty_=_params', 0),
                qty_at_params=data.get('qty_@_params', 0),
                qty_and_params=data.get('qty_&_params', 0),
                qty_exclamation_params=data.get('qty_!_params', 0),
                qty_space_params=data.get('qty_ _params', 0),
                qty_tilde_params=data.get('qty_~_params', 0),
                qty_comma_params=data.get('qty_,_params', 0),
                qty_plus_params=data.get('qty_+_params', 0),
                qty_asterisk_params=data.get('qty_*_params', 0),
                qty_hashtag_params=data.get('qty_#_params', 0),
                qty_dollar_params=data.get('qty_$_params', 0),
                qty_percent_params=data.get('qty_%_params', 0),
                params_length=data.get('params_length', 0),
                tld_present_params=data.get('tld_present_params', 0),
                qty_params=data.get('qty_params', 0),
                email_in_url=data.get('email_in_url', 0),
                time_response=data.get('time_response', 0.0),
                domain_spf=data.get('domain_spf', 0),
                asn_ip=data.get('asn_ip', 0),
                qty_ip_resolved=data.get('qty_ip_resolved', 0),
                qty_nameservers=data.get('qty_nameservers', 0),
                qty_mx_servers=data.get('qty_mx_servers', 0),
                ttl_hostname=data.get('ttl_hostname', 0),
                tls_ssl_certificate=data.get('tls_ssl_certificate', 0),
                qty_redirects=data.get('qty_redirects', 0),
                url_google_index=data.get('url_google_index', 0),
                domain_google_index=data.get('domain_google_index', 0),
                url_shortened=data.get('url_shortened', 0),
                time_domain_activation=data.get('time_domain_activation', 0),
                time_domain_expiration=data.get('time_domain_expiration', 0),
                phishing=feedback_type
                )
                
                # Save the instance to the database
                url_metrics.save()
                return HttpResponse('Success', status=200)
            except Exception as e:
                # Print the exception to the console for debugging
                print(f"Error saving URL metrics: {e}")
                return HttpResponse('Error saving data', status=500)
        else:
            return HttpResponse('Missing data', status=400)

    return HttpResponse('Invalid request method', status=400)
