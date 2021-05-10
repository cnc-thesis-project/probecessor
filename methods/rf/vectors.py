class Vectorizer():
    def get_default_vector(self):
        raise NotImplementedError


    def get_vector(self, prop):
        raise NotImplementedError


class ListOrderVectorizer(Vectorizer):
    def __init__(self, order_list):
        self.order_map = {}
        for i in range(len(order_list)):
            self.order_map[order_list[i]] = i


    def get_default_vector(self):
        return [-1] * len(self.order_map)


    def get_vector(self, headers):
        return list_to_order_list(list(map(str.lower, headers)), self.order_map)


# Takes a module and constructs a vector from each prop name
# using each vectorizer.
def construct_vector(props2vectorizers, module):
    vec = []
    for prop, vectorizer in props2vectorizers.items():
        val = module.get_property(prop)
        if not val:
            vec.extend(vectorizer.get_default_vector())
        else:
            vec.extend(vectorizer.get_vector(val))
    return vec


# Takes a list and a description list
# and returns a list describing the mutual order of the items
# from the description list in the list.
def list_to_order_list(li, desc):
    res = [-1 for i in range(len(desc.values()))]
    j = 0
    for i in range(len(li)):
        if li[i] in desc.keys():
            res[desc[li[i]]] = j
            j+=1
    return res
