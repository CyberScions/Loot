#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import re

class EXTRACTIONOPERATIONS():

    def InstagramAccessTokens(self, fwiat):

        found = []
        tokensrch = re.compile(r'[0-9]{7,10}\.[0-9a-f]{5,8}\.[0-9a-f]{32}')
        with open(fwiat, 'rb') as FileWithAccessToken:
            for token in FileWithAccessToken:
                token = token.replace('\n', '')
                if tokensrch.findall(token):
                    found.append(token)

        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique link(s)
        return u.keys()

    # Grab Bitcoin Wallet Addresses
    def BitcoinWalletAddress(self, fwbw):

        found = [] # List of found bitcoin wallet addresses
        btcwsrch = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
        with open(fwbw, 'rb') as FileWithBitcoinAddress:
            for wallet in FileWithBitcoinAddress:
                wallet = wallet.replace('\n', '')
                if btcwsrch.findall(wallet):
                    found.append(wallet)

        # remove duplicate link elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique link(s)
        return u.keys()

    # Grab password hashes
    def HashTypes(self, fohi):

        found = [] # List of found phone numbers
        md5srch = re.compile(r'[0-9a-f]{32}')
        sha1srch = re.compile(r'[0-9a-fA-F]{40}')
        sha256srch = re.compile(r'[0-9a-fA-F]{64}')
        sha384srch = re.compile(r'[0-9a-fA-F]{96}')
        sha512srch = re.compile(r'[0-9a-fA-F]{128}')


        with open(fohi, 'rb') as FileWithPhoneNumbers:
            for line in FileWithPhoneNumbers:
                hashtype = line.replace('\n', '')

                if md5srch.findall(hashtype):
                    found.append(hashtype)

                if sha1srch.findall(hashtype):
                    found.append(hashtype)

                if sha256srch.findall(hashtype):
                    found.append(hashtype)

                if sha384srch.findall(hashtype):
                    found.append(hashtype)

                if sha512srch.findall(hashtype):
                    found.append(hashtype)

        # remove duplicate phone number elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique phone number(s)
        return u.keys()

    def HyperLinks(self, fowl):

        found = [] # List of found links
        linksrch = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')

        with open(fowl, 'rb') as FileWithLinks:
            for line in FileWithLinks:
                links = line.replace('\n', '')
                if linksrch.findall(links):
                    found.append(links)

        # remove duplicate link elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique link(s)
        return u.keys()

    def IPv6Addresses(self, fowipv6):

        found = [] # List of found ipv6 numbers

        ipv6srch = re.compile(r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$")

        with open(fowipv6, 'rb') as FileWithCCN:
            for line in FileWithCCN:
                ipv6addr = line.replace('\n', '')
                if ipv6srch.findall(ipv6addr):
                    found.append(ipv6addr)

        # remove duplicate ipv6 elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique ssn numbers
        return u.keys()

    def CreditCardNumbers(self, foccn):
        # Supports detection for these Credit Card Types:

                # Visa
                # MasterCard
                # Discover
                # AMEX
                # Diners Club
                # JCB

        found = [] # List of found Credit card numbers

        ccsrch = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')

        with open(foccn, 'rb') as FileWithCCN:
            for line in FileWithCCN:
                cnumbers = line.replace('\n', '')
                if ccsrch.findall(cnumbers):
                    found.append(cnumbers)

        # remove duplicate Cred card number elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique CCN numbers
        return u.keys()

    def SSNs(self, fwssn):

        found = [] # List of found SSN numbers
        ssnsrch = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$') # USA based.
        ssnsrch2 = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$') # USA based.
        with open(fwssn, 'rb') as FileWithSSN:
            for line in FileWithSSN:
                numbers = line.replace('\n', '')

                if ssnsrch.findall(numbers): # adds SSN with (-) to list
                    found.append(numbers)

                if ssnsrch2.findall(numbers): # adds SSN without (-) to list
                    found.append(numbers)

        # remove duplicate ssn elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique ssn numbers
        return u.keys()

    def PhoneNumbers(self, fopn):

        found = [] # List of found phone numbers
        phonesrch = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$') # North american based.

        with open(fopn, 'rb') as FileWithPhoneNumbers:
            for line in FileWithPhoneNumbers:
                numbers = line.replace('\n', '')
                if phonesrch.findall(numbers):
                    found.append(numbers)

        # remove duplicate phone number elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique phone number(s)
        return u.keys()

    def MACs(self, fom):

        found = [] # List of found MAC (:, -, . deliminated) addresses
        macsrch = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
        macsrch1 = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')
        #macsrch1 = re.compile(r'([a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2}\-[a-fA-F0-9]{2})')

        with open(fom, 'rb') as FileWithMACS:
            for line in FileWithMACS:
                macs = line.replace('\n', '')

                if macsrch.findall(macs):
                    found.append(macs)

                if macsrch1.findall(macs):
                    found.append(macs)

        # remove duplicate MAC elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique mac addresses
        return u.keys()


    def IPv4Addresses(self, foi):

        found = [] # List of found ipv4 addresses
        ipv4srch = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')

        with open(foi, 'rb') as FileWithIPv4:
            for line in FileWithIPv4:
                ipv4 = line.replace('\n', '')
                if ipv4srch.findall(ipv4):
                    found.append(ipv4)

        # remove duplicate ipv4 elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique ipv4 addresses
        return u.keys()

    def Emails(self, foe):
        # if passed a list of text files, will return a list of
        # email addresses found in the files, matched according to
        # basic address conventions. Note: supports most possible
        # names, but not all valid ones.

        found = [] # List of found emails
        mailsrch = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

        with open(foe, 'rb') as FileWithEmail:
            for line in FileWithEmail:
                email = line.replace('\n', '')
                if mailsrch.findall(email):
                    found.append(email)
            #return found | for debugging, when the code goes out of style.

        # remove duplicate email elements
        u = {}
        for item in found:
            u[item] = 1

        #returns a list of unique email addresses
        return u.keys()

    def BlockchainIdentifiers(self, fobli):

        found = [] # List of found Blockchain Developer api keys
        mailsrch = re.compile(r'[0-9a-f]{5,8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{5,13}')
        with open(fobli, 'rb') as FileWithBlockchainIdentifiers:
            for line in FileWithBlockchainIdentifiers:
                identifiers = line.strip()
                if mailsrch.findall(identifiers):
                    found.append(identifiers)

        u = {}
        for item in found:
            u[item] = 1

        return u.keys()

    def FacebookAccessTokens(self, fofaat):

        found = [] # List of found Blockchain Developer api keys
        mailsrch = re.compile(r'access_token\=[0-9]{15}\|(.*){27}')
        with open(fofaat, 'rb') as FacebookAccessTokens:
            for line in FacebookAccessTokens:
                token = line.strip()
                if mailsrch.findall(token):
                    found.append(token)

        u = {}
        for item in found:
            u[item] = 1

        return u.keys()

extract = EXTRACTIONOPERATIONS()
