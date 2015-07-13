import os
import sys

class Utilities(object):

    def __init__(self):
        pass

    # Print data to the console
    def pi(self, pdata=''):
        print pdata
        
    # String boolean self-check.
    def string_bool_check(self, file_name, string): # Check if string is in a file.
        #return a NoneType if the string is not in the file.
        #.readlines() May be a problem is database files get too large.

        if os.path.exists(file_name) is False:
            MakeFile = open(file_name, 'a').close()

        if os.path.exists(file_name) is True:
            pass

        with open(file_name, 'r') as file:
            for item in file:
                item = item.replace("\n", '')
                if string.decode('utf-8').encode('utf-8') in item:
                    return True
