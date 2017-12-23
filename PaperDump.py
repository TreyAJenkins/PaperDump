#!/usr/bin/python
#Author: Trey Jenkins
#Version: 1.2.0

from fpdf import FPDF
from Crypto.Cipher import AES
import binascii, json, zlib, time, base64, qrcode, math, os, shutil, subprocess, magic, hashlib, pdf417gen

defblocksize = 1850.0
pdfblocksize = 800.0

def encode(string, name="", flags=""):
    data = {"NAME": name, "TIMESTAMP": time.time(), "TOTAL": None, "LENGTH": len(string), "SIZE": None, "BLOCK": None, "DATA": None, "FILETYPE": None, "FLAGS": flags, "SHA256": str(hashlib.sha256(string).hexdigest())}
    QR = []

    data["FILETYPE"] = magic.from_buffer(string)

    if name == "":
        data["NAME"] = "UNNAMED"

    cmp = zlib.compress(string)

    if len(cmp) < len(string):
        data["FLAGS"] = data["FLAGS"] + "[COMPRESSED] "
        print "Using ZLIB"
    else:
        cmp = string

    if "[FAX]" in flags:
	defblocksize = 1000.0

    if "[ENCRYPTED]" in flags:
        print "ENTER PASSWORD FOR ENCRYPTION"
        pw = raw_input("#> ")

        if len(pw) <= 32:
            pw = pw + "0" * (32 - len(pw))
        else:
            pw = pw[:32]

        m = str(hashlib.sha512(str(pw + "PAPERDUMP") * 2).hexdigest())[:16]
        obj = AES.new(pw, AES.MODE_CFB, m)
        cmp = obj.encrypt(cmp)
    pkt = base64.b64encode(cmp)
    data["SIZE"] = len(pkt)
    if "[PDF417]" in flags:
        blocksize = pdfblocksize - len(str(int(math.ceil(len(pkt) / pdfblocksize))))*2 - len(json.dumps(data))
    else:
        blocksize = defblocksize - len(str(int(math.ceil(len(pkt) / defblocksize))))*2 - len(json.dumps(data))
    print "Blocksize: " + str(blocksize)
    print "Length: " + str(len(pkt))
    blocks = int(math.ceil(len(pkt) / blocksize))
    data["TOTAL"] = blocks
    for i in range(0, blocks):
        print "Encoding block " + str(i+1) + " / " + str(blocks)
        dmp = {}
        cel = pkt[(i*int(blocksize)):((i+1)*int(blocksize))]
        dmp["DATA"] = cel
        data["DATA"] = cel
        data["BLOCK"] = i+1
        dmp["BLOCK"] = i+1
        dta = json.dumps(data)
        if "[PDF417]" in flags:
            codes = pdf417gen.encode(dta, columns=16)
            image = pdf417gen.render_image(codes)
            dmp["QR"] = image
        else:
            dmp["QR"] = qrcode.make(dta)
        QR.append(dmp)
    data["QR"] = QR
    return data

def generate(data, name="output.pdf"):
    print "Generating PDF"
    os.mkdir("tmp")
    pdf = FPDF("P", "in", "Letter")
    skipnext = False
    for key in data["QR"]:
        if not skipnext:
            print "Current block: " + str(key["BLOCK"])
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.cell(.25, .25, "Title: " + data["NAME"])
            pdf.ln()
            pdf.cell(.25, .25, "Block: " + str(key["BLOCK"]) + " / " + str(data["TOTAL"]))
            pdf.ln()
            pdf.cell(.25, .25, "Filetype: " + str(data["FILETYPE"]))
            pdf.ln()
            pdf.cell(.25, .25, "Flags: " + str(data["FLAGS"]))
            pdf.ln(4.25)
            key["QR"].save("tmp/tmp-" + str(key["BLOCK"]) + ".png")
            if "[PDF417]" in data["FLAGS"]:
                if int(key["BLOCK"]) < int(data["TOTAL"]):
                    pdf.image("tmp/tmp-" + str(key["BLOCK"]) + ".png", .28, 1.375, 7.94, 4.125)

                    data["QR"][int(key["BLOCK"])]["QR"].save("tmp/tmp-" + str(key["BLOCK"] + 1) + ".png")
                    pdf.image("tmp/tmp-" + str(int(key["BLOCK"]) + 1) + ".png", .28, 5.5, 7.94, 4.125)
                    pdf.cell(.25, .25, "Block: " + str(int(key["BLOCK"]) + 1) + " / " + str(data["TOTAL"]))

                    skipnext = True
                else:
                    pdf.image("tmp/tmp-" + str(key["BLOCK"]) + ".png", .125, 3.35, 8.25, 4.3)
            else:
                pdf.image("tmp/tmp-" + str(key["BLOCK"]) + ".png", .125, 1.375, 8.25, 8.25)
            pdf.ln(4.25)
            pdf.cell(.25, .25, "SHA256: " + str(data["SHA256"]))
        else:
            skipnext = False
    shutil.rmtree("tmp")
    pdf.output(name, "F")

def decode(pdfloc):
    print "Scanning PDF"
    r = subprocess.check_output(['zbarimg', '--raw', '-q', '-Sdisable', '-Sqrcode.enable', pdfloc])
    data = r.split("\n")
    data = data[:-1]
    info = {"NAME": None, "TIMESTAMP": None, "TOTAL": None, "LENGTH": None, "SIZE": None, "DATA": None, "FILETYPE": None, "SHA256": None}
    blocks = {}

    for d in data:
        dat = json.loads(d)
        if info["SHA256"] == None:
            info["SHA256"] = dat["SHA256"]
        else:
            if info["SHA256"] != dat["SHA256"]:
                print "ERROR: BLOCK " + str(dat["BLOCK"]) + ' "' + str(dat["NAME"]) + '"' + " DOES NOT BELONG WITH THIS DATA"
                return -1
        info["NAME"] = dat["NAME"]
        info["TIMESTAMP"] = dat["TIMESTAMP"]
        info["TOTAL"] = dat["TOTAL"]
        info["LENGTH"] = dat["LENGTH"]
        info["SIZE"] = dat["SIZE"]
        info["FILETYPE"] = dat["FILETYPE"]
        info["FLAGS"] = dat["FLAGS"]


        blocks[dat["BLOCK"]] = dat["DATA"]
    if len(blocks) < int(info["TOTAL"]):
        print "# BLOCKS MISSING: " + str(int(info["TOTAL"]) - len(blocks))
        ba = ""
        for k in blocks:
            ba = ba + str(k) + " "
        print "BLOCKS AVAILABLE: " + ba
        return -1
    pkt = ""
    for i in range(0, int(info["TOTAL"])):
        v = i+1
        print "Decoding block " + str(v) + " / " + str(info['TOTAL'])
        pkt = pkt + blocks[v]

    pkt = base64.b64decode(pkt)
    if "[ENCRYPTED]" in info["FLAGS"]:
        print "ENTER PASSWORD FOR DECRYPTION"
        pw = raw_input("#> ")

        if len(pw) <= 32:
            pw = pw + "0" * (32 - len(pw))
        else:
            pw = pw[:32]

        m = str(hashlib.sha512(str(pw + "PAPERDUMP") * 2).hexdigest())[:16]
        obj = AES.new(pw, AES.MODE_CFB, m)
        print "Decrypting"
        pkt = obj.decrypt(pkt)

    if "[COMPRESSED]" in info["FLAGS"]:
        print "Decompressing"
        pkt = zlib.decompress(pkt)
    info["DATA"] = pkt
    return info
