import tlsh

def get_data(mod):
    return {"tlsh": mod.get_property("tlsh"), "port": mod.port}

def match(mod_data1, mod_data2):
    try:
        diff = tlsh.diff(mod_data1["tlsh"], mod_data2["tlsh"])
    except:
        return False
    #print("TLSH diff between {} and {}:".format(mod_data1["port"], mod_data2["port"]), diff)
    return diff < 50
