#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Ref - https://github.com/surajr/URL-Classification/blob/master/URL%20Classification.ipynb

import sys
import os
from os.path import splitext
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pickle as pkl
import ipaddress
import tldextract
#import whois # (pip install python-whois)
from urlparse import urlparse
import re
import logging
import base64
import urllib2

import sklearn.ensemble as ek
from sklearn import cross_validation,tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.linear_model import LogisticRegression
from sklearn import svm
from sklearn import preprocessing
from sklearn.metrics import confusion_matrix
from sklearn.naive_bayes import GaussianNB
from sklearn.externals import joblib
from sklearn.pipeline import make_pipeline

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

# extract callable that falls back to the included TLD snapshot, no live HTTP fetching
# https://github.com/john-kurkowski/tldextract
tld_extract = tldextract.TLDExtract(suffix_list_urls=None)

# Count no of dots in domain
def count_dots(url):
    return url.count('.')

# Count no of delimiters
def count_delimiters(url):
    delim = 0
    delim_chars = [';', '_', '?', '=', '&']
    for char in url:
        if char in delim_chars:
            delim +=1
    return delim

# Check if ip is present in string
def ip_in_string(str):
    r_exp=re.compile('\\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\b')
    response = r_exp.findall(str)
    if response:
        #return response
        return True 
    # else: return None
    else: return False

# Check if ip is present in url string
def ip_in_url(url):
    r_exp=re.compile('\\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\b')
    u = urlparse(url)
    response = r_exp.findall(u.netloc)
    if response:
        #return response
        return True
    #else: return None
    else: return False

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
    url_results = urlparse(url)
    #return [url_results.scheme,url_results.netloc,url_results.path,url_results.params,url_results.query,url_results.fragment]
    return pd.Series((url_results.scheme,url_results.netloc,url_results.path,url_results.params,url_results.query,url_results.fragment))


def url_domain_info(url):
    url_results = tld_extract(url)
    return pd.Series((url_results.domain, url_results.subdomain, url_results.suffix))


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

#print list(set(tld_domains))

# Top 10 malicious domains - Trendmicro report
# http://apac.trendmicro.com/apac/security-intelligence/current-threat-activity/malicious-top-ten/
# do automatic extraction of top 10 malicious domains using beautifulsoup/scapy

malware_domains = ['trafficconverter.biz','www.funad.co.kr','deepspacer.com',
'tags.expo9.exponential.com','bembed.redtube.comr','dl.baixaki.com.br',
'www.trafficholder.com','mattfoll.eu.interia.pl','www.luckytime.co.kr']


df = pd.read_csv('dataset.csv')
#df = pd.read_csv('single_entry.csv')
#print df.head()
#print df.tail()

# decode/unquote the url
df['URL'] = df.apply(lambda row: url_decode(row['URL']), axis=1)

# url length
df['url_length'] = df.apply(lambda row: len(row['URL']),axis=1)

# url delimiters
df['url_delimiter'] = df.apply(lambda row: count_delimiters(row['URL']),axis=1)

# count hypen characters in url
df['hypen_char_url'] = df.apply(lambda row: count_hypen(row['URL']), axis=1)

# count slash characters in url
df['slash_char_url'] = df.apply(lambda row: count_slash(row['URL'].split('://')[1]), axis=1)

# count doubleslash characters in url
df['doubleslash_char_url'] = df.apply(lambda row: count_doubleslash(row['URL'].split('://')[1]), axis=1)

# count at characters in url
df['at_char_url'] = df.apply(lambda row: count_at_symbol(row['URL']), axis=1)

# get extension(useful for tracking the file that is downloaded.)
df['extension'] = df.apply(lambda row: get_extension(row['URL']), axis=1)

# check if ip is present in url
df['ip_in_url'] = df.apply(lambda row: ip_in_url(row['URL']), axis=1)

# url parameters
df[['url_scheme','url_netloc','url_path','url_parameters','url_query','url_fragment']] \
   = df.apply(lambda row: url_parameters(row['URL']), axis=1)

# url domain details
df[['url_domain', 'url_subdomain', 'url_suffix']] \
   = df.apply(lambda row: url_domain_info(row['URL']), axis=1)

# dots in domain
df['dots_domain'] = df.apply(lambda row: count_dots(row['url_domain']),axis=1)

# length of domain
df['length_domain'] = df.apply(lambda row: len(row['url_domain']),axis=1)

# dots in subdomain
df['dots_subdomain'] = df.apply(lambda row: count_dots(row['url_subdomain']),axis=1)

# length of subdomain
df['length_subdomain'] = df.apply(lambda row: len(row['url_subdomain']),axis=1)


# count url query parameters
df['url_query_parameters'] = df.apply(lambda row: count_queries(row['url_query']), axis=1)

# check if url query is base64 encoded
df['url_query_base64'] = df.apply(lambda row: detect_base64_string(row['url_query']), axis=1)

# count url subdomains
df['url_subdomains'] = df.apply(lambda row: count_subdomains(row['url_subdomain']), axis=1)

# count hypen characters in domain
df['hypen_char_fulldomain'] = df.apply(lambda row: count_hypen(row['url_domain'] + row['url_subdomain'] + row['url_suffix']), axis=1)


#print df[:1].values
#print df.head()

####################
## Visualization - distribution of variables
#####################

#sns.set(style="darkgrid")
#sns.distplot(df[df['Lable']==0]['url_length'],color='green',label='Benign URLs')
#sns.distplot(df[df['Lable']==1]['url_length'],color='red',label='Phishing URLs')
#plt.title('url length distribution')
#plt.legend(loc='upper right')
#plt.xlabel('url length')
#plt.show()


#sns.distplot(df[df['Lable']==0]['hypen_char_url'],color='green',label='Benign URLs')
#sns.distplot(df[df['Lable']==1]['hypen_char_url'],color='red',label='Phishing URLs')
#plt.title('hypen char distribution')
#plt.legend(loc='upper right')
#plt.xlabel('hypen chars')
#plt.show()

#sns.distplot(df[df['Lable']==0]['length_domain'],color='green',label='Benign URLs')
#sns.distplot(df[df['Lable']==1]['length_domain'],color='red',label='Phishing URLs')
#plt.title('domain length distribution')
#plt.legend(loc='upper right')
#plt.xlabel('domain length')
#plt.show()

#sns.distplot(df[df['Lable']==0]['length_subdomain'],color='green',label='Benign URLs')
#sns.distplot(df[df['Lable']==1]['length_subdomain'],color='red',label='Phishing URLs')
#plt.title('domain length distribution')
#plt.legend(loc='upper right')
#plt.xlabel('domain length')
#plt.show()

print df.groupby(df['Lable']).size()

X = df.drop(['URL','Lable','extension','url_scheme','url_netloc','url_path','url_parameters','url_query','url_fragment','url_domain', 'url_subdomain', 'url_suffix'],axis=1).values
y = df['Lable'].values

model = { "DecisionTree":tree.DecisionTreeClassifier(max_depth=10),
         "RandomForest":ek.RandomForestClassifier(n_estimators=50),
         "Adaboost":ek.AdaBoostClassifier(n_estimators=50),
         "GradientBoosting":ek.GradientBoostingClassifier(n_estimators=50),
         "GNB":GaussianNB(),
         "LogisticRegression":LogisticRegression()   
}

# cross validation
X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, y ,test_size=0.2)

results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)
    print ("%s : %s " %(algo, score))
    results[algo] = score

winner = max(results, key=results.get)
print(winner)

clf = model[winner]
res = clf.predict(X)
mt = confusion_matrix(y, res)
print mt
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))

