#-*- coding: utf-8 -*-
from __future__ import print_function
import sys, re, argparse, json, httplib2, time
from urllib import *
from urllib2 import *
from urlparse import *

PURPLE = '\033[95m' #HEADER 
BLUE = '\033[94m' #OK BLUE
GREEN = '\033[92m' #OK GREEN
ORANGE = '\033[93m' #WARNING
RED = '\033[91m' #FAIL
ENDC = '\033[0m'
BOLD = '\033[1m' 
UNDERLINE = '\033[4m'

SAFETY = 1
EXPLOITABLE = 2
UNKNOWN = 3
ERROR = 4

def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Open Redirect fuzzer v1.0', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', metavar='https://target.com?'+ORANGE+'redirect_url={}'+ENDC, type=str, help="Enter the address you want to collect, including the protocol, argument.")
    parser.add_argument('-t', '--txt', metavar='<filename>', type=str, help='Enter the FUZZ list file.\nDefault=fuzz.list', default='fuzz.list')
    parser.add_argument('-c', '--cookies', metavar='<cookies>', type=str, help='Enter the cookie with session.\nEx) "JSESSIONID:AWER; PHPSESSIONID=AAA;"', default='')
    parser.add_argument('-w', '--whitelist', metavar='<URL>',type=str, help='Enter If different whitelist from target.\nEx) https://whitelists.com')
    parser.add_argument('-X', '--method', metavar='<Method>', type=str, help='Support Only GET or POST.\nDefault=GET', default='GET')
    parser.add_argument('-d', '--data', metavar='<POST_data>', type=str, help='HTTP POST data.\nEx) id=id&pw=pw&'+ORANGE+'redirect_url={}'+ENDC, default='')
    parser.add_argument('-H', '--headers', metavar='<header>', type=str, help='Pass custom header to server',nargs='*', default=['Content-Type: application/x-www-form-urlencoded'])
    #parser.add_argument('-o', '--output', metavar='<filename>', type=str, help='Enter the Output filename.')
    args = parser.parse_args()
    print(args.headers)

def DisplayInitData(headers, parse):
    
    ascii = '''
              _ _               _      __
 _ __ ___  __| (_)_ __ ___  ___| |_   / _|_   _ ___________ _ __
| '__/ _ \/ _` | | '__/ _ \/ __| __| | |_| | | |_  /_  / _ \ '__|
| | |  __/ (_| | | | |  __/ (__| |_  |  _| |_| |/ / / /  __/ |
|_|  \___|\__,_|_|_|  \___|\___|\__| |_|  \__,_/___/___\___|_|
                                    
                                       Developed by @smlee   v1.0
    '''
    print('{}{}{}'.format(PURPLE,ascii,ENDC))
    print('{}[+] Dest      : {}{}'.format(GREEN, ENDC, args.target))
    print('{}[+] Method    : {}{}'.format(GREEN, ENDC, args.method))
    print('{}[+] Whitelist : {}{}'.format(GREEN, ENDC, args.whitelist))
    print('{}[+] FileName  : {}{}'.format(GREEN, ENDC, args.txt))
    print('{}[+] Header    : {}{}'.format(GREEN, ENDC, headers))
    print('{}[+] Data      : {}{}'.format(GREEN, ENDC, args.data))
    print('{}[+] protocol  : {}{}'.format(GREEN, ENDC, parse))
    time.sleep(2)


def parseResultFromStatus(header, body, redirect):

    if header['status'] in ['301', '302', '307']:
        if redirect == header['location']:
            return EXPLOITABLE
            
    elif header['status'] in ['200']:
        if body.find(redirect) != -1:
            return EXPLOITABLE

    elif header['status'] in ['500']:
        return ERROR
    else:
        return UNKNOWN

    return SAFETY

def printResult(status, result, redirect):
    print('[{STATUS}]'.format(STATUS=status).format(), end='')

    if result == SAFETY:
        print('{COLOR}[+] Safety      : {ENDC}'.format(COLOR=GREEN, ENDC=ENDC), end='')
    elif result == EXPLOITABLE:
        print('{COLOR}[-] Exploitable : {ENDC}'.format(COLOR=RED, ENDC=ENDC), end='')
    elif result == ERROR:
        print('{COLOR}[-] ERROR       : {ENDC}'.format(COLOR=PURPLE, ENDC=ENDC), end='')
    elif result == UNKNOWN:
        print('{COLOR}[-] UNKNOWN     : {ENDC}'.format(COLOR=ORANGE, ENDC=ENDC), end='')

    print('{COLOR}{redirect}{ENDC}'.format(COLOR=BLUE,redirect=redirect, ENDC=ENDC))

def isJsonString(str):
    try:
        #print(str)
        json.loads(str)
    except ValueError as e:
        print('param is not json string')
        return False
    return True

def toFormatJSONString(json_str, fuzz_data):
    json_data = json.loads(json_str)
    for key in json_data:
        if json_data[key].find('{}') != -1:
            json_data[key] = json_data[key].format(fuzz_data)

    return json.dumps(json_data)

def requestFuzzing(headers, redirect):
    #httplib2.debuglevel = 4
    http = httplib2.Http("", disable_ssl_certificate_validation=True)
    http.follow_redirects = False

    if args.method == 'GET':              
        fuzz = args.target.format(quote_plus(redirect, safe='%/:;(){}<>[],.+\\@?"\''))
        return http.request(fuzz, 'GET', '', headers=headers)                
    elif args.method == 'POST' and args.target.find('{}') != -1:
        fuzz = args.target.format(quote_plus(redirect, safe='%/:;(){}<>[],.+\\@?"\''))
        return http.request(fuzz, 'POST', args.data, headers=headers)
    elif args.method == 'POST' and args.data.find('{}') != -1:
        if isJsonString(args.data): #json string
            fuzz = toFormatJSONString(args.data, quote_plus(redirect, safe='%/:;(){}<>[],.+\\@?"\''))
            print(fuzz)
        else:
            fuzz = args.data.format(quote_plus(redirect, safe='%/:;(){}<>[],.+\\@?"\''))
        
        return http.request(args.target, 'POST', fuzz, headers=headers)
    else:
        fuzz = args.target.format(quote_plus(redirect, safe='%/:;(){}<>[],.+\\@?"\''))
        return http.request(fuzz, 'GET', '', headers=headers)                

def startFuzzing():

    #Set Arguments
    target = args.target
    data = args.data
    args.method = args.method.upper()
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cookie": args.cookies
    }
    for header in args.headers:
        key, value = header.split(':')
        headers[key] = value
    
    #Parse URL
    if args.whitelist != None:
        parse = urlparse(args.whitelist) # https://whitlist.com/path
        if parse.scheme != '':
            args.whitelist = parse.hostname
    elif args.whitelist == '':
        parse = urlparse(args.target) # https://target.com/login?redirect={}
        parse.hostname = ''
        parse.path = ''
        parse.query = ''
    else:
        parse = urlparse(args.target) # https://target.com/login?redirect={}

    #scheme = parse.scheme # https
    #path = parse.path # /login
    #query = parse.query # redirect_url=
    #hostname = parse.hostname # target.com


    DisplayInitData(headers, parse)

    print('{}[+] =======================  START  ======================={}'.format(GREEN, ENDC))
    with open(args.txt, 'r') as fp:
        fuzz_lists = fp.read().splitlines()
        for line in fuzz_lists:
            
            if args.whitelist != None:
                redirect = line.format(protocol=parse.scheme, target=args.whitelist)
            else:    
                redirect = line.format(protocol=parse.scheme, target=parse.hostname)
            #print(headers)
            #print(redirect)
            (res_hdr, res_body) = requestFuzzing(headers=headers, redirect=redirect)
            #print(res_hdr, res_body)
           
            time.sleep(0.1)
            result = parseResultFromStatus(header=res_hdr, body=res_body, redirect=redirect)

            printResult(status=res_hdr['status'], result=result, redirect=redirect)
            
            #debug
            if res_hdr['status'][0] == '3':
                print("302 Location : ", res_hdr['location'])
            
        fp.close()

    print('{}[-] =======================   END   ======================={}'.format(GREEN, ENDC))


def main():
    parse_args()
    startFuzzing()

if __name__ == '__main__':
    main()


