class Label():
    def __init__(self, mwdb_id, label, port):
        self.mwdb_id = mwdb_id
        self.label = label
        self.port = port

    @staticmethod
    def to_str(labels, delimiter="/"):
        # convert labels into a string like: mirai/Dridex/QakBot
        label_set = set(map(lambda l: l.label, labels))
        if len(label_set) == 0:
            label_set.add("unlabeled")
        return delimiter.join(sorted(label_set))
