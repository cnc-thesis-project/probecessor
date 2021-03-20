def get_label_names(host):
    # TODO
    return
    labels = set()
    for l in host.get_labels():
        labels.add(l["type"])
    if len(labels) == 0:
        labels.add("unlabeled")
    labels = '/'.join(sorted(labels))

    return labels
