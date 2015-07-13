import datetime
from functions import Utilities

class Exportation(Utilities):

    def __init__(self):
        self.current_time = datetime.datetime.now().strftime("%I-%M%p_%B_%d_%Y")
        self.exportfile = 'bagged_goods' + "_" + str(self.current_time) + '.txt'

    def export_file(self, findings):
        with open(self.exportfile, 'a+') as file:
            bc = self.string_bool_check(self.exportfile, findings.decode('utf-8'))
            if bc is None:
                file.write(findings + "\n")
