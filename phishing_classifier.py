#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Ref - https://github.com/surajr/URL-Classification/blob/master/URL%20Classification.ipynb

import sys
import os
from os.path import splitext
import pandas as pd
import numpy as np
import matplotlib.pylab as plt
import ipaddress
import tldextract
import whois
from urlparse import urlparse
import datetime
import re
import logging
import base64
import urllib2

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

# Count no of dots in domain
def count_dots(url):
    return url.count('.')

# Count no of delimiters
def count_delimiters(url):
    delim = 0
    delim = [';', '_', '?', '=', '&']
    for char in url:
        if char in delim:
            delim +=1
    return count

# Check if ip is present in string
def ip_in_string(str):
    r_exp=re.compile('\\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\b')
    response = r_exp.findall(str)
    if response:
        return response
    else: return None

# Check if ip is present in url string
def ip_in_url(url):
    r_exp=re.compile('\\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\b')
    u = urlparse(url)
    response = r_exp.findall(u.netloc)
    if response:
        return response
    else: return None

# Check if string is base64 encoded
def detect_base64_string(base64_string):
    #Ref - https://stackoverflow.com/questions/12315398/verify-is-a-string-is-encoded-in-base64-python
    try:
        if base64.b64encode(base64.b64decode(base64_string)) == base64_string:
            return True;
    except Exception:
        pass;
    return False;

# encode url string
def url_encode(encode_string):
    return urllib2.quote(encode_string)

# decode url string
def url_decode(decode_string):
    return urllib2.unquote(decode_string).decode('utf8')

# check if '-' is present
def count_hypen(url):
    return url.count('-')

# check no of '/' in url
def count_slash(url):
    return url.count('/')

# Existence of “//” within the URL path implies that user will be redirected to another website. An example of such URL’s is: “http://www.legitimate.com//http://www.phishing.com”. so, we examine the presence of “//”
# check no of '//' in url
def count_doubleslash(url):
    return url.count('//')

# Using “@” symbol in the URL leads the browser to ignore everything preceding “@” symbol and the real address often follows the “@” symbol.
# check presence of @ character
def count_at_symbol(url):
    return url.count('@')

# return file name extension from url 
def get_extension(url):
    root,ext = splitext(url)
    return ext

# count no of subdomains
def count_subdomains(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))

# count no of url queries
def count_queries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))

def url_parameters(url):
    url_dict = dict()
    url_results = urlparse(url)
    url_dict['scheme'] = url_results.scheme
    url_dict['netloc'] = url_results.netloc
    url_dict['path'] = url_results.path
    url_dict['params'] = url_results.params
    url_dict['query'] = url_results.query
    url_dict['fragment'] = url_results.fragment
    return url_dict

def url_domain_info(url):
    url_info = dict()
    url_results = tldextract.extract(url)
    url_dict['domain'] = url_results.domain
    url_dict['subdomain'] = url_results.subdomain
    url_dict['suffix'] = url_results.suffix



df = pd.read_csv('dataset.csv')
print df.head()
print df.tail()

# Top 20 suspicious domains - Symantec report
# https://www.symantec.com/blogs/feature-stories/top-20-shady-top-level-domains
# do automatic extraction of tld domains using python libraries like beautifulsoup or scapy

tld_domains = ['.country','.stream','.download','.xin','.gdn','.racing',
'.jetzt','.win','.bid','.vip','.ren','.kim','.loan','.mom','.party','.review',
'.trade','.date','.wang','.accountants','.xyz','.cricket','.win','.space',
'.stream','.christmas','.gdn','.mom','.pro','.faith','.science','.mem']

# some custom tld domains
custom_tld_domains = ['.ru','.pk','.cn', 'pw','top','ga','ml']

tld_domains += custom_tld_domains

print list(set(tld_domains))

# Top 10 malicious domains - Trendmicro report
# http://apac.trendmicro.com/apac/security-intelligence/current-threat-activity/malicious-top-ten/
# do automatic extraction of top 10 malicious domains using beautifulsoup/scapy

malware_domains = ['trafficconverter.biz','www.funad.co.kr','deepspacer.com',
'tags.expo9.exponential.com','bembed.redtube.comr','dl.baixaki.com.br',
'www.trafficholder.com','mattfoll.eu.interia.pl','www.luckytime.co.kr']

def get_features(url):
    # extract features from url
    results = list()
    # url
    results.append( str(url) )

    # length of url
    results.append(len(url))

    # count delimiters
    results.append(count_delimiters(url))

    # url parameters
    url_results = url_parameters(url)
    results.append(url_results['scheme'])
    results.append(url_results['netloc'])
    results.append(url_results['path'])
    results.append(url_results['params'])
    results.append(url_results['query'])
    results.append(url_results['fragment'])

    # url domain info
    domain_results =url_domain_info(url)
    results.append(domain_results['domain'])
    results.append(domain_results['subdomain'])
    results.append(domain_results['suffix'])

    # count query parameters in url
    results.append(count_queries(url_results['query']))

    # count subdomains
    results.append(count_subdomains(domain_results['subdomain']))

    # no of dots in subdomain
    results.append(count_dots(domain_results['subdomain'])

    # no of delimites in domain
    results.append(count_delimiters(domain_results['domain']))

    # no of delimites in subdomain
    results.append(count_delimiters(domain_results['subdomain']))

    # count no of subdirectories :'/'
    results.append(count_slash(url_results['path']))

    # count no of doubleslash:'//'
    results.append(count_doubleslash(url_results['path']))

    # count @ in url
    results.append(count_at_symbol(url_results['netloc']))

    # count '-' in domain
    results.append(count_hypen(url_results['netloc']))

    # length of domain
    results.append(len(domain_results['domain']))

    # length of subdomain
    results.append(len(domain_results['subdomain']))

