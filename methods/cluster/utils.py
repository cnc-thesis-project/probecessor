def cluster_module_data(mod_data):
    model = module_models.get(mod_data["type"])
    if not model:
        return
    norm_port["cluster"] = model.predict([norm_port["vector"]])[0]
    trns = model.transform([norm_port["vector"]])
    norm_port["distance"] = min(trns[0])


def match_module_clusters(mod_data1, mod_data2):
    cluster1 = mod_data1.get("cluster")
    cluster2 = mod_data2.get("cluster")

    if not cluster1:
        cluster1 = cluster_module_data(mod_data1)
    if not cluster2:
        cluster2 = cluster_module_data(mod_data2)

    if cluster1 == cluster2:
        return True

    return False
