from flask import Flask,request,jsonify
import socket
from urllib.parse import urlparse
import idna
import tldextract
import re
import pandas as pd
import os
import requests
from nltk.tokenize import word_tokenize
from collections import Counter
from bs4 import BeautifulSoup
import whois
import datetime
# import pickle
import numpy as np
# from joblib import dump, load
# import dns.resolver
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
# from sklearn.linear_model import LogisticRegression
# from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score

data = pd.read_csv("dataset_B_05_2020.csv")
# data.head(10)
y = data['status']
data.drop(['status'], axis=1)
x = data.drop(['status','url'], axis=1)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier())
])
pipeline.fit(x_train, y_train)
y_pred = pipeline.predict(x_test)
score = accuracy_score(y_test, y_pred)
def has_ip(url):
    try:
        hostname = urlparse(url).hostname
        socket.inet_aton(hostname)
        return 1
    except:
        return 0


def has_puny(url):
    try:
        hostname = str(urlparse(url).hostname)
        idna.decode(hostname)
        return 1
    except idna.IDNAError:
        return 0


def has_tld_in_path(url):
    try:
        extracted = tldextract.extract(url)
        path = urlparse(url).path
        return extracted.suffix in path
    except:
        return 0


def sub_tld(url):
    try:
        subdomain = urlparse(url).hostname.split(".")[0]
        extracted = tldextract.extract(url)
        return extracted.suffix in subdomain
    except:
        return 0


def abnormal_sub(url):
    try:
        subdomain = urlparse(url).hostname.split(".")[0]
        return bool(re.search(r'[^a-zA-Z0-9-]', subdomain))
    except:
        return 0


def has_random_domain(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split('.')[-2]
        df = pd.DataFrame({'url': [url]})
        df['abnormal_subdomain'] = df['url'].apply(lambda x: '.' in domain and domain.replace('-', '').isalnum())
        return df['abnormal_subdomain'][0]
    except:
        return 0


def has_shortening_service(url):
    try:
        parsed_url = urlparse(url)
        df = pd.DataFrame({'url': [url]})
        df['shortening_service'] = df['url'].apply(
            lambda x: 'bit.ly' in parsed_url.netloc or 'tinyurl.com' in parsed_url.netloc)
        return df['shortening_service'][0]
    except:
        return 0


def path_extension(url):
    try:
        path = urlparse(url).path
        return os.path.splitext(path)[1]
    except:
        return 0


def num_of_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirects = len(response.history)
        return redirects
    except:
        return 0


def external_redirections(url):
    try:
        response = requests.get(url, allow_redirects=True)
        num_external_redirections = 0
        for r in response.history:
            if r.is_redirect and r.url.split('/')[2] != url.split('/')[2]:
                num_external_redirections += 1
        return num_external_redirections
    except:
        return 0


def chars_repeat(url):
    try:
        characters = list(urlparse(url).hostname)
        frequency = Counter(characters)
        repeated_characters = [char for char, count in frequency.items() if count > 1]
        return len(repeated_characters)
    except:
        return 0


def shortest_word(url):
    try:
        words = url.split("/")
        words2 = url.split(".")
        words3 = urlparse(url).hostname.split(".")
        result = words + words2 + words3
        m = len(url)
        for e in result:
            if len(e) == 0:
                continue
            elif m > len(e):
                m = len(e)
        return m
    except:
        return 0


def shortest_word_host(host):
    try:
        words = host.split(".")
        m = len(host)
        for e in words:
            if len(e) == 0:
                continue
            elif m > len(e):
                m = len(e)
        return m
    except:
        return 0


def shortest_word_path(path):
    try:
        words = path.split("/")
        m = len(path)
        for e in words:
            if len(e) == 0:
                continue
            elif m > len(e):
                m = len(e)
        return m
    except:
        return 0


def longest_word(url):
    try:
        words = url.split("/")
        words2 = url.split(".")
        words3 = urlparse(url).hostname.split(".")
        result = words + words2 + words3
        m = 0
        for e in result:
            if len(e) == 0 or "/" in e or "." in e:
                continue
            elif m < len(e):
                m = len(e)
        return m
    except:
        return 0


def longest_host(host):
    words = str(host).split(".")
    m = 0
    for e in words:
        if len(e) == 0:
            continue
        elif m < len(e):
            m = len(e)
    return m


def longest_path(path):
    words = path.split("/")
    m = 0
    for e in words:
        if len(e) == 0:
            continue
        elif m < len(e):
            m = len(e)
    return m


def suspecious_tld(url):
    try:
        tlds = ["com", "edu", "net", "org", "gov"]
        tld = urlparse(url).netloc.split(".")[-1]
        return 1 if tld not in tlds else 0
    except:
        return 0


def statistical_report(url):
    try:
        statistical_keywords = ['stats', 'statistics', 'reports', 'analytics']
        for keyword in statistical_keywords:
            if keyword in url.lower():
                return True
        return False
    except:
        return False


def num_hyper(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        hyperlinks = soup.find_all("a")
        return len(hyperlinks)
    except:
        return 0


def external_css(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")

        css_files = []
        for css in soup.find_all("link", rel="stylesheet"):
            if css.attrs.get("href"):
                css_url = css.attrs.get("href")
                if css_url.startswith("http"):
                    css_files.append(css_url)
        return len(css_files)
    except:
        return 0


def login_form(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            if form.find("input", {"type": "password"}):
                return 1
                break
        else:
            return 0
    except:
        return 0


def external_favicon(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        favicon = soup.find("link", rel="icon")
        if favicon:
            return 1
        else:
            return 0
    except:
        return 0


def empty_title(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string
        if title:
            return 0
        else:
            return 1
    except:
        return 0


def domain_in_title(url):
    try:
        domain = urlparse(url).netloc.split('.')[-2]
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string
        return domain in title
    except:
        return 0


def domain_copyright(url):
    try:
        domain = whois.whois(url).domain
        return bool(re.search(r'©️', domain))
    except:
        return 0


def is_registered(url):
    try:
        domain_info = whois.whois(url)
        return domain_info.creation_date
    except Exception:
        return False


def domain_age(url):
    try:
        domain_info = whois.whois(url)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        age = (datetime.datetime.now() - creation_date).days
        return age
    except:
        return -1


def dns_records(url):
    try:
        ip_address = socket.gethostbyname(url)
        return 1
    except socket.gaierror:
        return 0


def google_indexed(url):
    search_url = f'https://www.google.com/search?q=site:{url}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all('div', {'class': 'tF2Cxc'})

        return any(url in result.text for result in results)

    except:
        return 0


def features(url):
    if url is not None:
        result = {}
        parsed_url = urlparse(url)
        result["url_length"] = len(url)
        result["host_length"] = len(str(parsed_url.hostname))
        result["ip"] = has_ip(url)
        result["dots"] = url.count(".")
        result["hypens"] = url.count("-")
        result["at"] = url.count("@")
        result["que"] = url.count("?")
        result["and"] = url.count("&")
        result["or"] = url.count("|")
        result["eq"] = url.count("=")
        result["under"] = url.count("_")
        result["tilde"] = url.count("~")
        result["per"] = url.count("%")
        result["slash"] = url.count("/")
        result["star"] = url.count("*")
        result["colon"] = url.count(":")
        result["comma"] = url.count(",")
        result["semi"] = url.count(";")
        result["dollar"] = url.count("$")
        result["space"] = url.count(" ")
        result["www"] = url.count("www")
        result["com"] = url.count("com")
        result["dbslash"] = url.count("//")
        result["http_in"] = 1 if "http" in url else 0
        result["https_in"] = 1 if "https" in url else 0
        num_digits = 0
        for i in range(len(url)):
            if url[i].isdigit():
                num_digits = num_digits + 1
        result["ratio_char_digits"] = 0 if num_digits == 0 else round(num_digits / len(url), 9)
        host_digits = 0
        for j in range(len(str(parsed_url.hostname))):
            if str(parsed_url.hostname)[j].isdigit():
                host_digits = host_digits + 1
        result["ratio_host_char_digits"] = 0 if host_digits == 0 else round(host_digits / len(parsed_url.hostname), 9)
        result["punycode"] = has_puny(url)
        result["port"] = 1 if parsed_url.port else 0
        result["has_tld"] = 1 if has_tld_in_path(url) else 0
        result["sub_tld"] = 1 if sub_tld(url) else 0
        result["abnormal_sub"] = 1 if abnormal_sub(url) else 0
        result["nb_subdomain"] = url.count(str(urlparse(url).hostname).split(".")[0])
        result["prefix_suffix"] = 1 if url.startswith("htts://") and url.endswith(".com") else 0
        result["rand_domain"] = 1 if has_random_domain(url) else 0
        result["shortening_service"] = 1 if has_shortening_service(url) else 0
        result["path_extension"] = 1 if path_extension(url) else 0
        result["redirects"] = num_of_redirects(url)
        result["external_redirects"] = external_redirections(url)
        result["length_url_words"] = len(word_tokenize(parsed_url.geturl()))
        result["char_repeat"] = chars_repeat(url)
        result["shortest_word"] = shortest_word(url)
        result["shortest_word_host"] = shortest_word_host(parsed_url.hostname)
        result["shortest_path"] = shortest_word_path(parsed_url.path)
        result["longest_word"] = longest_word(url)
        result["longest_host"] = longest_host(parsed_url.hostname)
        result["longest_path"] = longest_path(parsed_url.path)
        result["suspecious_tld"] = suspecious_tld(url)
        result["statistical_report"] = 1 if statistical_report(url) else 0
        result["nb_hyper"] = num_hyper(url)
        result["external_css"] = external_css(url)
        result["login_form"] = login_form(url)
        result["favicon"] = external_favicon(url)
        result["empty_title"] = empty_title(url)
        result["domain_title"] = 1 if domain_in_title(url) else 0
        result["domain_cp"] = 1 if domain_copyright(url) else 0
        result["whois_registered"] = 1 if is_registered(url) else 0
        result["domain_age"] = domain_age(url)
        result["dns_record"] = dns_records(url)
        result["google_index"] = 1 if google_indexed(url) else 0

        # print(len(result))
        return result
    else:
        return 0


# print(features("https://umassloust.com/online"))
# model = pickle.load(open('detection.pkl','rb'))
# model = load('newmodel.joblib', 'r')
app = Flask("__name__")

@app.route('/')
def home():
    return "Hello World"

@app.route('/predict',methods=['POST'])
def predict():
    url = str(request.form["url"])
    output = features(url)
    values = list(output.values())
    array_values = np.array([values])
    result = pipeline.predict(array_values)[0]
    if result != 'phishing':
        return '0'
    # result1 = json.dumps(result)
    else:
        return '1'


if __name__ == '__main__':
    app.run(host="0.0.0.0")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

