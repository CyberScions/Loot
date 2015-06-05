#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import re
from storage import database
from extraction import extract
from functions import utilities
from core.info import notifications

class PROCESSEXTRACT():

    def InstagramAccessToken(self, file):
        IATExtract = extract.InstagramAccessTokens(file) # Collected emails

        if len(IATExtract) is 0:
            utilities.pi("{}No Instagram access tokens in {}".format(notifications.FAIL, file))

        if len(IATExtract) > 0: # legit file, containing at least 1 email address.
            FoundIATs = [] # Re-filter, so you get exactly what you're looking for.
            for instance in IATExtract:
                IATRegex = re.compile(r'[0-9]{7,10}\.[0-9a-f]{5,8}\.[0-9a-f]{32}')
                IATContainer = IATRegex.search(instance)
                IATs = IATContainer.group()
                FoundIATs.append(IATs)
            UOD = {}
            for item in FoundIATs:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------------------------")
            utilities.pi("      EXTRACTED Instagram access tokens     ")
            utilities.pi("--------------------------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} instagram access token from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} instagram access tokens from {}\n".format(str(count), file))

    def Emails(self, file):
        EmailExtract = extract.Emails(file) # Collected emails

        if len(EmailExtract) is 0:
            utilities.pi("{}No Emails in {}".format(notifications.FAIL, file))

        if len(EmailExtract) > 0: # legit file, containing at least 1 email address.
            FoundEmails = [] # Re-filter, so you get exactly what you're looking for.
            for instance in EmailExtract:
                EmailRegex = re.compile(r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
                EmailContainer = EmailRegex.search(instance)
                Emails = EmailContainer.group()
                FoundEmails.append(Emails)
            UOD = {}
            for item in FoundEmails:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED Emails    ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Email Address from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Email Addresses from {}\n".format(str(count), file))

    def IPv4Addresses(self, file):
        IPv4Extract = extract.IPv4Addresses(file) # Collected ipv4s

        if len(IPv4Extract) is 0:
            utilities.pi("{}No IPv4 addresses in {}".format(notifications.FAIL, file))

        if len(IPv4Extract) > 0: # legit file, containing at least 1 ipv4 address.
            FoundIPv4s = [] # Re-filter, so you get exactly what you're looking for.
            for instance in IPv4Extract:
                IPv4Regex = re.compile(r'([0-9]+)(?:\.[0-9]+){3}')
                IPv4Container = IPv4Regex.search(instance)
                IPv4s = IPv4Container.group()
                FoundIPv4s.append(IPv4s)
            UOD = {}
            for item in FoundIPv4s:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED IPV4s     ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} IPv4 address from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} IPv4 addresses from {}\n".format(str(count), file))

    def MACAddresses(self, file):
        MACExtract = extract.MACs(file)

        if len(MACExtract) is 0:
            utilities.pi("{}No MAC addresses in {}".format(notifications.FAIL, file))

        if len(MACExtract) > 0: # legit file, containing at least 1 MAC, (: or - deliminated) address.
            FoundMACS = [] # Re-filter, so you get exactly what you're looking for.
            for instance in MACExtract:
                macsrch = re.compile(r'([0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})')
                macsrch1 = re.compile(r'([0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2})')
                cdm = macsrch.findall(instance)
                hdm = macsrch1.findall(instance)
                for mach in hdm: FoundMACS.append(mach)
                for macc in cdm: FoundMACS.append(macc)
            UOD = {}
            for item in FoundMACS:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED MACs      ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "{} Extracted MAC address from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "{} Extracted MAC addresses from {}\n".format(str(count), file))

    def PhoneNumbers(self, file):
        PNExtract = extract.PhoneNumbers(file)

        if len(PNExtract) is 0:
            utilities.pi("{}No Phone numbers in {}".format(notifications.FAIL, file))

        if len(PNExtract) > 0 and len(PNExtract[0]) < 15: # Try not to grab any CCNs
            FoundPhoneNumbers = [] # Re-filter, so you get exactly what you're looking for.
            for instance in PNExtract:
                PNRegex = re.compile(r'(\d{3})\D*(\d{3})\D*(\d{4})\D*(\d*)$')
                PNC = PNRegex.search(instance)
                PN = PNC.group()
                FoundPhoneNumbers.append(PN)
            UOD = {}
            for item in FoundPhoneNumbers:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi(" EXTRACTED Phone Numbers  ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                if output.isdigit() is False and ":" not in output and "@" not in output:
                    utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "{} Extracted Phone Number(s) from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "{} Extracted Phone Number(s) from {}\n".format(str(count), file))

        if len(PNExtract) is 15:
            utilities.pi("{}No Phone numbers in {}".format(notifications.FAIL, file))

    def SocialSecurityNumbers(self, file):
        SSNExtract = extract.SSNs(file)

        if len(SSNExtract) is 0:
            utilities.pi("{}No Social securtiy numbers in {}".format(notifications.FAIL, file))

        if len(SSNExtract) > 0: # legit file, containing at least 1 SSN, ( - deliminated) number.
            FoundSSNs = [] # Re-filter, so you get exactly what you're looking for.
            for instance in SSNExtract:
                SSN1Regex = re.compile(r'^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$')
                SSN2Regex = re.compile(r'^(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}$')
                SSN1LIST = SSN1Regex.findall(instance) # no deliminator
                SSN2LIST = SSN2Regex.findall(instance) # - deliminator
                for SSNV1 in SSN1LIST: FoundSSNs.append(SSNV1)
                for SSNV2 in SSN2LIST: FoundSSNs.append(SSNV2)
            UOD = {}
            for item in FoundSSNs:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED SSNs      ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Social security number  from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Social security numbers  from {}\n".format(str(count), file))

    def CreditCardNumbers(self, file):
        CCNExtract = extract.CreditCardNumbers(file)

        if len(CCNExtract) is 0:
            utilities.pi("{}No Creditcard numbers in {}".format(notifications.FAIL, file))

        if len(CCNExtract) > 0: # legit file, containing at least 1 CCN  numbers.
            FoundCCNs = [] # Re-filter, so you get exactly what you're looking for.
            for instance in CCNExtract:
                CCNRegex = re.compile(r'^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$')
                CCNLIST = CCNRegex.search(instance)
                CCN = CCNLIST.group()
                FoundCCNs.append(CCN)
            UOD = {}
            for item in FoundCCNs:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED CCNs      ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Creditcard number from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Creditscard numbers from {}\n".format(str(count), file))

    def IPv6Addresses(self, file):
        IPv6Extract = extract.IPv6Addresses(file)

        if len(IPv6Extract) is 0:
            utilities.pi("{}No IPv6 addresses in {}".format(notifications.FAIL, file))

        if len(IPv6Extract) > 0: # legit file, containing at least 1 ipv6 number.
            FoundIPV6s = [] # Re-filter, so you get exactly what you're looking for.
            for instance in IPv6Extract:
                IPv6Regex = re.compile(r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$')
                IPv6List = IPv6Regex.search(instance)
                IPv6s = IPv6List.group()
                FoundIPV6s.append(IPv6s)

            UOD = {}
            for item in FoundIPV6s:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED IPv6s     ")
            utilities.pi("--------------------------")
            count = 0

            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} IPv6 address from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} IPv6 addresses from {}\n".format(str(count), file))

    def HyperLinks(self, file):

        LinkExtract = extract.HyperLinks(file)

        if len(LinkExtract) is 0:
            utilities.pi("{}No Links in {}".format(notifications.FAIL, file))

        if len(LinkExtract) > 0: # legit file, containing at least 1 link.
            FoundLinks = [] # Re-filter, so you get exactly what you're looking for.
            for instance in LinkExtract:
                LinkExtractRegex = re.compile(r'^((https|ftp|http|data|dav|cid|chrome|apt|cvs|bitcoin|dns|imap|irc|ldap|mailto|magnet|proxy|res|rsync|rtmp|rtsp|shttp|sftp|skype|ssh|snmp|snews|svn|telnet|tel|tftp|udp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$')
                LinkList = LinkExtractRegex.search(instance)
                Links = LinkList.group()
                FoundLinks.append(Links)
            UOD = {}
            for item in FoundLinks:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("      EXTRACTED links     ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} link from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} links from {}\n".format(str(count), file))

    def BTCAddresses(self, file):
        BTCWAExtract = extract.BitcoinWalletAddress(file)

        if len(BTCWAExtract) is 0:
            utilities.pi("{}No Bitcoin addresses in {}".format(notifications.FAIL, file))

        if len(BTCWAExtract) > 0: # legit file, containing at least 1 link.
            FoundWallets = [] # Re-filter, so you get exactly what you're looking for.

            for instance in BTCWAExtract:
                BTCWalletRegex = re.compile(r'(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,30}(?![a-km-zA-HJ-NP-Z0-9])|(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{33,35}(?![a-km-zA-HJ-NP-Z0-9])')
                wallet = BTCWalletRegex.findall(instance)
                for address in wallet: FoundWallets.append(address)
            UOD = {}
            for item in FoundWallets:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("  EXTRACTED BTC Addresses ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Bitcoin address from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Bitcoin addresses from {}\n".format(str(count), file))


    def HashTypes(self, file):
        HashExtract = extract.HashTypes(file)

        if len(HashExtract) is 0:
            utilities.pi("{}No Hashes in {}".format(notifications.FAIL, file))

        if len(HashExtract) > 0: # If you actually grab something then continue
            FoundHashes = [] # Re-filter, so you get exactly what you're looking for.

            for instance in HashExtract:
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
                for md5 in md5list: FoundHashes.append(md5)
                for sha1 in sha1list: FoundHashes.append(sha1)
                for sha256 in sha256list: FoundHashes.append(sha256)
                for sha384 in sha384list: FoundHashes.append(sha384)
                for sha512 in sha512list: FoundHashes.append(sha512)

            UOD = {} # Filter out any duplicates
            for item in FoundHashes:
                UOD[item] = 1 # No duplicates at all !
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("   Extracted Hash Values  ")
            utilities.pi("--------------------------")
            count = 0
            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Hash found from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Hash(es) found from {}\n".format(str(count), file))


    def FacebookAccessTokens(self, file):
        FATExtract = extract.FacebookAccessTokens(file)

        if len(FATExtract) is 0:
            utilities.pi("{}No Facebook Access Tokens in {}".format(notifications.FAIL, file))

        if len(FATExtract) > 0:
            FoundFATs = [] # Re-filter, so you get exactly what you're looking for.
            for instance in FATExtract:
                FATRegex = re.compile(r'(access_token\=[0-9]{15}\|(.*){27})')
                FATList = FATRegex.search(instance)
                FATs = FATList.group()
                FoundFATs.append(FATs)

            UOD = {}
            for item in FoundFATs:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("  Facebook Access Tokens  ")
            utilities.pi("--------------------------")
            count = 0

            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Facebook Access Token from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Facebook Access Tokens from {}\n".format(str(count), file))

    def BlockchainIdentifiers(self, file):
        BCIDSExtract = extract.BlockchainIdentifiers(file)
        if len(BCIDSExtract) is 0:
            utilities.pi("{}No Blockchain Identifiers in {}".format(notifications.FAIL, file))

        if len(BCIDSExtract) > 0:
            FoundBCIDS = [] # Re-filter, so you get exactly what you're looking for.
            for instance in BCIDSExtract:
                BCIDSRegex = re.compile(r'[0-9a-f]{5,8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{5,13}')
                BCIDSList = BCIDSRegex.search(instance)
                BCIDSs = BCIDSList.group()
                FoundBCIDS.append(BCIDSs)

            UOD = {}
            for item in FoundBCIDS:
                UOD[item] = 1
            keys = UOD.keys()
            utilities.pi("--------------------------")
            utilities.pi("  Blockchain Identifiers  ")
            utilities.pi("--------------------------")
            count = 0

            for output in keys:
                database.ExportFile(output)
                count += 1
                utilities.pi(notifications.INFO + output)

            if count is 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Blockchain Identifier from {}\n".format(str(count), file))

            elif count > 1:
                utilities.pi("\n" + notifications.STATUS + "Extracted {} Blockchain Identifiers from {}\n".format(str(count), file))

output = PROCESSEXTRACT()
