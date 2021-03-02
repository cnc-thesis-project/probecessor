import tlsh

def fp(data):
    if len(data) > 50:
        return tlsh.hash(data)
    else:
        return data
