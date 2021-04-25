import math
import sys

def print_progress(done, total, estimated_time=None):
    if total == 0:
        return
    print("\r", end="")

    estimate_text=""
    if estimated_time:
        estimate_text="{} seconds remaining".format(estimated_time)

    prog = (done/total)*10
    print("[" + int(prog)*"=" + math.ceil(10-prog)*"-" + "] {0:.2f}% ({1}/{2}) {3}".format(prog*10, done, total, estimate_text), end="")
    sys.stdout.flush()
