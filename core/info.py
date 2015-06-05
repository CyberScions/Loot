#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

from core.libs.colors import paint

class COLOREDOUTPUT():

    INFO = paint.W+"[FOUND]"+paint.N+": "
    FAIL = paint.R+"[FAILED]"+paint.N+": "
    STATUS = paint.Y+"[RESULTS]"+paint.N+": "

notifications = COLOREDOUTPUT()

def Help():
    print """
    [GWF Certified] - https://twitter.com/GuerrillaWF

    Loot - Extract sensitive information from a file.

    Usage: ./loot.py -f [FILE] [OPTION]

    Options:

    --btc   | Grab bitcoin addresses if any are in file.
    --blid  | Grab Blockchain Identifiers if any are in file.
    --fat   | Grab Facebook Access Tokens if any are in file.
    --mac   | Grab MAC addresses if any are in file.
    --iat   | Grab instagram access tokens if any are in file.
    --fat   | Grab facebook access tokens if any are in file
    --ssn   | Grab social security numbers if any are in file.
    --ccn   | Grab credit card numbers if any are in file.
    --ipv6  | Grab IPv6 addresses if any are in file.
    --ipv4  | Grab IPv4 addresses if any are in file.
    --email | Grab Email addresses if any are in file.
    --hash  | Grab hash values if any are in file.
    --phn   | Grab phone numbers if any are in file.
    """
