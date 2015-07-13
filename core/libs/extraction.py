import re

class extract(object):

    def __init__(self):
        self.__found = []
        self.__unique = {}

    def InstagramAccessTokens(self, file):
        self.token = re.compile(r'[0-9]{7,10}\.[0-9a-f]{5,8}\.[0-9a-f]{32}')

        with open(file, 'rb') as __file:
            for token in __file:
                token = token.strip()
                if self.token.findall(token):
                    self.__found.append(token)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def BitcoinWalletAddress(self, file):
        self.btc = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
        with open(file, 'rb') as __file:
            for wallet in __file:
                self.address = wallet.strip()
                if self.btc.findall(self.address):
                    self.__found.append(self.address)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def HashTypes(self, file):
        self.md5 = re.compile(r'[0-9a-f]{32}')
        self.sha1 = re.compile(r'[0-9a-fA-F]{40}')
        self.sha256 = re.compile(r'[0-9a-fA-F]{64}')
        self.sha384 = re.compile(r'[0-9a-fA-F]{96}')
        self.sha512 = re.compile(r'[0-9a-fA-F]{128}')

        with open(file, 'rb') as __file:
            for line in __file:
                self.hashtype = line.strip()

                if self.md5.findall(self.hashtype):
                    self.__found.append(self.hashtype)

                if self.sha1.findall(self.hashtype):
                    self.__found.append(self.hashtype)

                if self.sha256.findall(self.hashtype):
                    self.__found.append(self.hashtypee)

                if self.sha384.findall(self.hashtype):
                    self.__found.append(self.hashtype)

                if self.sha512.findall(self.hashtype):
                    self.__found.append(self.hashtype)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def HyperLinks(self, file):
        self.regex = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp|git)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')

        with open(file, 'rb') as __file:
            for line in __file:
                self.links = line.strip()
                if self.regex.findall(self.links):
                    self.__found.append(self.links)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def IPv6Addresses(self, file):
        self.regex = re.compile(r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$")

        with open(file, 'rb') as __file:
            for line in __file:
                self.ipv6 = line.strip()
                if self.regex.findall(self.ipv6):
                    self.__found.append(self.ipv6)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def CreditCardNumbers(self, file):
        # Supports detection for these Credit Card Types:

                # Visa
                # MasterCard
                # Discover
                # AMEX
                # Diners Club
                # JCB

        self.regex = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')

        with open(file, 'rb') as __file:
            for line in __file:
                self.ccns = line.strip()
                if self.regex.findall(self.ccns):
                    self.__found.append(self.ccns)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def SSNs(self, file):
        self.ssnv1 = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$') # USA based.
        self.ssnv2 = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$') # USA based.

        with open(file, 'rb') as __file:
            for line in __file:
                self.numbers = line.strip()

                if self.ssnv1.findall(self.numbers):
                    self.__found.append(self.numbers)

                if self.ssnv2.findall(self.numbers):
                    self.__found.append(self.numbers)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def PhoneNumbers(self, file):
        self.regex = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$')

        with open(file, 'rb') as __file:
            for line in __file:
                self.numbers = line.strip()
                if self.regex.findall(self.numbers):
                    self.__found.append(self.numbers)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def MACs(self, file):
        self.macv1 = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
        self.macv2 = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')

        with open(file, 'rb') as __file:
            for line in __file:
                self.mac = line.strip()

                if self.macv1.findall(self.mac):
                    self.__found.append(self.mac)

                if self.macv2.findall(self.mac):
                    self.__found.append(self.mac)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def IPv4Addresses(self, file):
        self.regex = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')

        with open(file, 'rb') as __file:
            for line in __file:
                self.ipv4 = line.strip()
                if self.regex.findall(self.ipv4):
                    self.__found.append(self.ipv4)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def Emails(self, file):
        mailsrch = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

        with open(file, 'rb') as __file:
            for line in __file:
                email = line.strip()
                if mailsrch.findall(email):
                    self.__found.append(email)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def BlockchainIdentifiers(self, file):
        self.regex = re.compile(r'[0-9a-f]{5,8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{5,13}')

        with open(file, 'rb') as __file:
            for line in __file:
                self.identifiers = line.strip()
                if self.regex.findall(self.identifiers):
                    self.__found.append(self.identifiers)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()

    def FacebookAccessTokens(self, file):
        self.regex = re.compile(r'access_token\=[0-9]{15}\|(.*){27}')

        with open(file, 'rb') as __file:
            for line in __file:
                self.token = line.strip()
                if self.regex.findall(self.token):
                    self.__found.append(self.token)

        for item in self.__found:
            self.__unique[item] = 1
        return self.__unique.keys()
