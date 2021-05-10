import methods.rf.models


def cluster_module_data(mod_data):
    if not mod_data.get("vector"):
        print("WARNING: NO VECTOR FOR {}".format(mod_data["module"]))
        return
    model = methods.rf.models.models.get(mod_data["module"])
    if not model:
        #print("WARNING: NO MODEL FOR {}".format(mod_data["module"]))
        return
    mod_data["cluster"] = model.predict([mod_data["vector"]])[0]
    #trns = model.transform([mod_data["vector"]])
    #mod_data["distance"] = min(trns[0])


def match_module_clusters(mod_data1, mod_data2):
    cluster1 = mod_data1.get("cluster")
    cluster2 = mod_data2.get("cluster")

    if not cluster1:
        cluster1 = cluster_module_data(mod_data1)
        mod_data1["cluster"] = cluster1
    if not cluster2:
        cluster2 = cluster_module_data(mod_data2)
        mod_data2["cluster"] = cluster2

    if cluster1 == cluster2:
        return True

    return False
