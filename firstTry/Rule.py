
class Rule:
    def __init__(self, name, meta, strings, condition):
        self.name = name
        self.meta = meta
        self.strings = strings
        self.condition = condition