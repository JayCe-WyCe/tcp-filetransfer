# debug class

class debug:
    
    def __init__(self, mode=False):
        self.mode = mode

    def log(self, message):
        if(self.mode):
            print(f"{message}")
