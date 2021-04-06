import math
import sys

def print_progress(done, total):
    if total == 0:
        return
    print("\r", end="")

    prog = (done/total)*10
    print("[" + int(prog)*"=" + math.ceil(10-prog)*"-" + "] {0:.2f}% ({1}/{2})".format(prog*10, done, total), end="")
    sys.stdout.flush()
