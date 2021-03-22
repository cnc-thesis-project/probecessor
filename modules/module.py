class Module():
    def __init__(self, name):
        self.name = name


    def add_data(self, row):
        raise NotImplementedError


    def get_property(self, name):
        raise NotImplementedError


    # Should return an iterable of tuples with key-value
    def get_properties(self):
        raise NotImplementedError


    def has_property(self, name):
        raise NotImplementedError
