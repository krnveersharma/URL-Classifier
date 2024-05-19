from flask import Flask, jsonify, request
import tldextract
import requests
import re
from urllib.parse import urlparse, parse_qs
import dns.resolver
import whois
from datetime import datetime
import pickle
import numpy as np
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
# Load the model from the .pkl file
with open('classifier.pkl', 'rb') as pkl_file:
    model = pickle.load(pkl_file)

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

# Route for extracting features from a URL and making predictions
@app.route('/extract_features_and_predict', methods=['POST'])
def extract_features_and_predict():
    url = request.json.get('url')
    if url:
        features = extract_features(url)
        if model:
            sample_features_array = np.array([list(features.values())])
            predictions = model.predict(sample_features_array)
            return jsonify({'features': features, 'predictions': predictions.tolist()})
        else:
            return jsonify({'error': 'Model not loaded'}), 500
    else:
        return jsonify({'error': 'URL not provided'}), 400

# Main block
if __name__ == '__main__':
    app.run(debug=True)
# 1=> possibly phished
# 0=> might not be phished