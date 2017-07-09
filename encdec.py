#!/usr/bin/python
#Author: Trey Jenkins
#Version: 1.0.0

import sys, PaperDump, os

def encode(inp, outp):
    with open(inp, 'rb') as f:
        data = f.read()

    flags = ""

    r = raw_input("Set flags? [y/N] > ")
    if "Y" in r.upper():
        flags = raw_input("Flags: ") + " "

    r = raw_input("Encrypt? [y/N] > ")
    if "Y" in r.upper():
        flags = flags + "[ENCRYPTED] "

    enc = PaperDump.encode(data, name=os.path.basename(inp), flags=flags)
    PaperDump.generate(enc, outp)

def decode(inp, outp):
    data = PaperDump.decode(inp)

    if data == -1:
        sys.exit()

    print "NAME:     " + data["NAME"]
    print "FLAGS:    " + data["FLAGS"]
    print "FILETYPE: " + data["FILETYPE"]

    with open(outp, 'wb') as f:
        data = f.write(data["DATA"])



print "PaperDump\n"
print "Encode or Decode?"
r = raw_input("[E/D] > ")
if r.upper() == "E":
    r = raw_input("Input file: ")
    if os.path.exists(r):
        o = raw_input("Output file: ")
        encode(r, o)
    else:
        print "File does not exist"
        sys.exit()
elif r.upper() == "D":
    r = raw_input("Input file: ")
    if os.path.exists(r):
        o = raw_input("Output file: ")
        decode(r, o)
    else:
        print "File does not exist"
        sys.exit()
