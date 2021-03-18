def get_label_names(host_data):
    labels = set()
    for l in host_data.get("label", []):
        labels.add(l["type"])
    if len(labels) == 0:
        labels.add("unlabeled")
    labels = '/'.join(sorted(labels))

    return labels
