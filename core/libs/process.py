#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import re
from storage import Exportation
from extraction import extract
from functions import Utilities
from core.info import notifications

class Take(Utilities):

    def __init__(self):
        self.__found = []
        self.__unique = {}
        self.__extract = extract()
        self.__export = Exportation()
        self.__notify = notifications()

    def InstagramAccessToken(self, file):
        self.get = self.__extract.InstagramAccessTokens(file)

        if len(self.get) is 0:
            self.pi("{}No Instagram access tokens in {}".format(self.__notify.FAIL, file))

        if len(self.get) > 0: # legit file, containing at least 1 email address.
            for instance in self.get:
                self.regex = re.compile(r'[0-9]{7,10}\.[0-9a-f]{5,8}\.[0-9a-f]{32}')
                self.container = self.regex.search(instance)
                self.iats = self.container.group()
                self.__found.append(self.iats)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------------------------")
            self.pi("      EXTRACTED Instagram access tokens     ")
            self.pi("--------------------------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} instagram access token from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} instagram access tokens from {}\n".format(str(self.count), file))

    def Emails(self, file):
        self.get = self.__extract.Emails(file)

        if len(self.get) is 0:
            self.pi("{}No Emails in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
                self.container = self.regex.search(instance)
                self.emails = self.container.group()
                self.__found.append(self.emails)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED Emails    ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique:
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Email Address from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Email Addresses from {}\n".format(str(self.count), file))

    def IPv4Addresses(self, file):
        self.get = self.__extract.IPv4Addresses(file)

        if len(self.get) is 0:
            self.pi("{}No IPv4 addresses in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0: # legit file, containing at least 1 ipv4 address.

            for instance in self.get:
                self.regex = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')
                self.container = self.regex.search(instance)
                self.ipv4s = self.container.group()
                self.__found.append(self.ipv4s)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED IPV4s     ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} IPv4 address from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} IPv4 addresses from {}\n".format(str(self.count), file))

    def MACAddresses(self, file):
        self.get = self.__extract.MACs(file)

        if len(self.get) is 0:
            self.pi("{}No MAC addresses in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0: # legit file, containing at least 1 MAC, (: or - deliminated) address.
            for instance in self.get:
                self.macv1 = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')
                self.macv2 = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
                self.colon = self.macv1.findall(instance)
                self.hyphen = self.macv2.findall(instance)
                for colon_deliminator in self.colon: self.__found.append(colon_deliminator)
                for hyphen_deliminator in self.hyphen : self.__found.append(hyphen_deliminator)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED MACs      ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "{} Extracted MAC address from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "{} Extracted MAC addresses from {}\n".format(str(self.count), file))

    def PhoneNumbers(self, file):
        self.get = self.__extract.PhoneNumbers(file)

        if len(self.get) is 0:
            self.pi("{}No Phone numbers in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0 and len(PNExtract[0]) < 15: # Try not to grab any CCNs
            for instance in self.get:
                self.regex = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$')
                self.regex.container = self.regex.search(instance)
                self.phone = self.regex.container.group()
                self.__found.append(self.phone)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi(" EXTRACTED Phone Numbers  ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                if output.isdigit() is False and ":" not in output and "@" not in output:
                    self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "{} Extracted Phone Number from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "{} Extracted Phone Number(s) from {}\n".format(str(self.count), file))

        if len(self.__extract.PhoneNumbers(file)) is 15:
            self.pi("{}No Phone numbers in {}".format(self.__notify.FAIL, file))

    def SocialSecurityNumbers(self, file):
        self.get = self.__extract.SSNs(file)

        if len(self.get) is 0:
            self.pi("{}No Social securtiy numbers in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0:
            for instance in self.get:
                self.regex1 = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$')
                self.regex2 = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$')
                self.list1 = self.regex1.findall(instance) # no deliminator
                self.list2 = self.regex2.findall(instance) # - deliminator
                for SSNV1 in self.list1: self.__found.append(SSNV1)
                for SSNV2 in self.list2: self.__found.append(SSNV2)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED SSNs      ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Social security number  from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Social security numbers  from {}\n".format(str(self.count), file))

    def CreditCardNumbers(self, file):
        self.get = self.__extract.CreditCardNumbers(file)

        if len(self.get) is 0:
            self.pi("{}No Creditcard numbers in {}".format(self.__notify.FAIL, file))

        if len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')
                self.container = self.regex.search(instance)
                self.list = self.container.group()
                self.__found.append(self.list)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED CCNs      ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Creditcard number from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Creditscard numbers from {}\n".format(str(self.count), file))

    def IPv6Addresses(self, file):
        self.get = self.__extract.IPv6Addresses(file)

        if len(self.get) is 0:
            self.pi("{}No IPv6 addresses in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$')
                self.list = self.regex.search(instance)
                self.ipv6s = self.list.group()
                self.__found.append(self.ipv6s)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED IPv6s     ")
            self.pi("--------------------------")
            self.count = 0

            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} IPv6 address from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} IPv6 addresses from {}\n".format(str(self.count), file))

    def HyperLinks(self, file):
        self.get = self.__extract.HyperLinks(file)

        if len(self.get) is 0:
            self.pi("{}No Links in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0: # legit file, containing at least 1 link.
            for instance in self.get:
                self.regex = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')
                self.list = self.regex.search(instance)
                self.links = self.list.group()
                self.__found.append(self.links)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("      EXTRACTED links     ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} link from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} links from {}\n".format(str(self.count), file))

    def BTCAddresses(self, file):
        self.get = self.__extract.BitcoinWalletAddress(file)

        if len(self.get) is 0:
            self.pi("{}No Bitcoin addresses in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
                self.wallet = self.regex.findall(instance)
                for address in self.wallet: self.__found.append(address)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("  EXTRACTED BTC Addresses ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Bitcoin address from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Bitcoin addresses from {}\n".format(str(self.count), file))

    def HashTypes(self, file):
        self.get = self.__extract.HashTypes(file)

        if len(self.get) is 0:
            self.pi("{}No Hashes in {}".format(self.__notify.FAIL, file))

        if len(self.get) > 0: # If you actually grab something then continue
            for instance in self.get:
                # Stand-alone regex's for finding hash values.

                md5regex = re.compile(r'[a-fA-F0-9]{32}')
                sha1regex = re.compile(r'[[a-fA-F0-9]{40}')
                sha256regex = re.compile(r'[a-fA-F0-9]{64}')
                sha384regex = re.compile(r'[a-fA-F0-9]{96}')
                sha512regex = re.compile(r'[a-fA-F0-9]{128}')

                # Find hash value of given regex's
                md5list = md5regex.findall(instance)
                sha1list = sha1regex.findall(instance)
                sha256list = sha256regex.findall(instance)
                sha384list = sha384regex.findall(instance)
                sha512list = sha512regex.findall(instance)

                # Add hash values to un-filtered list for filtering.
                for md5 in md5list: self.__found.append(md5)
                for sha1 in sha1list: self.__found.append(sha1)
                for sha256 in sha256list: self.__found.append(sha256)
                for sha384 in sha384list: self.__found.append(sha384)
                for sha512 in sha512list: self.__found.append(sha512)

            for item in self.__found:
                self.__unique[item] = 1 # No duplicates at all !

            self.pi("\n--------------------------")
            self.pi("   Extracted Hash Values  ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Hash found from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Hash(es) found from {}\n".format(str(self.count), file))

    def FacebookAccessTokens(self, file):
        self.get = self.__extract.FacebookAccessTokens(file)

        if len(self.get) is 0:
            self.pi("{}No Facebook Access Tokens in {}".format(self.__notify.FAIL, file))

        if len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'(access_token\=[0-9]{15}\|(.*){27})')
                self.list = self.regex.search(instance)
                self.fats = self.list.group()
                self.__found.append(self.fats)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("  Facebook Access Tokens  ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Facebook Access Token from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Facebook Access Tokens from {}\n".format(str(self.count), file))

    def BlockchainIdentifiers(self, file):
        self.get = self.__extract.BlockchainIdentifiers(file)

        if len(self.get) is 0:
            self.pi("{}No Blockchain Identifiers in {}".format(self.__notify.FAIL, file))

        elif len(self.get) > 0:
            for instance in self.get:
                self.regex = re.compile(r'[0-9a-f]{5,8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{5,13}')
                self.list = self.regex.search(instance)
                self.bcids = self.list.group()
                self.__found.append(self.bcids)

            for item in self.__found:
                self.__unique[item] = 1

            self.pi("\n--------------------------")
            self.pi("  Blockchain Identifiers  ")
            self.pi("--------------------------")

            self.count = 0
            for output in self.__unique.keys():
                self.__export.export_file(output)
                self.count += 1
                self.pi(self.__notify.INFO + output)

            if self.count is 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Blockchain Identifier from {}\n".format(str(self.count), file))

            elif self.count > 1:
                self.pi("\n" + self.__notify.STATUS + "Extracted {} Blockchain Identifiers from {}\n".format(str(self.count), file))
