import base64

def run(rows):
    return {"response": base64.b64encode(rows[0]["data"]).decode()}
