
# Class useful for manipulating colors

class Color :

    def __init__(self) :

        self.endc = '\033['
        self.end  ="\033[0m"

        self.green = '92m'
        self.fail = '91m'
        self.yellow = '93m'
        self.purple = '37m'
        self.blue = '96m'

        self.normal = '0'
        self.bold = ''
        self.underline = '2'

    def color(self, text, options):

        # \033[1;32;40m

        if options:
            for color in options :
                return F"{self.endc}{color}{text}{self.end}"

    def status (self, text):
        return self.color(text, [self.green])

    def error (self, text):
        return self.color(text, [self.fail])

    def yellows (self, text):
        return self.color(text, [self.yellow])

    def purple (self, text):
        return self.color(text, [self.purple])

    def blues (self, text):
        return self.color(text, [self.blue])