import base64
import sys
import traceback
import requests
import os
import re
import hashlib
import tempfile
from xml.etree import ElementTree
from optparse import OptionParser
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
from pikepdf import Pdf

req_data = """<?xml version="1.0" encoding="UTF-8"?>
<auth-req>
<file-id>{}</file-id>
<doi/>
</auth-req>
"""
iv_first = b"200CFC8299B84aa980E945F63D3EF48D"
iv_first = iv_first[:16]


class CustomException(Exception):
    pass


def aes_decrypt(key, iv, data, pad=False):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    ret = dec.update(data) + dec.finalize()
    if not pad:
        return ret
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(ret) + unpadder.finalize()


def request_password(url, file_id):
    r = requests.post(url, headers={
        "User-Agent": "Readerdex 2.0",
        "Cache-Control": "no-cache"
    }, data=req_data.format(file_id))
    if r.status_code != 200:
        raise CustomException(
            "[Error] Server Error. Try again later...\n[Debug] FileId: {}".format(file_id))
    try:
        root = ElementTree.fromstring(r.text)
    except Exception:
        raise CustomException(
            "[Error] Invilid response.\n[Debug] FileId: {}".format(file_id))
    password = root.find("./password").text
    if not password or not password.strip():
        raise CustomException(
            "[Error] Failed to get password. The original file is probably out of date. Please check it out and then try again...\n[Debug] FileId:{}".format(file_id))
    return password.strip()


def decrypt_file_key(password_from_file, password_from_server, iv_from_file, right_meta, rights):
    pass_dec = aes_decrypt(password_from_server, iv_first,
                           base64.b64decode(password_from_file))
    m = hashlib.sha256()
    m.update(pass_dec[:0x20])
    m.update(right_meta)
    sha256 = m.digest()
    iv_second = base64.b64decode(iv_from_file)
    rights_dec = aes_decrypt(sha256, iv_second[:16], base64.b64decode(rights))
    m = re.search(r"<encrypt>([0-9a-f]+)</encrypt>",
                  rights_dec.decode("utf-8"))
    if not m:
        raise CustomException("[Error] Failed to get the encryption key...\n[Debug]: {}", rights_dec)
    pass_in_rights = m.group(1)
    pass_in_rights += "AppendCA"
    m = hashlib.sha1()
    m.update(pass_in_rights.encode("utf-8"))
    return m.digest()[:0x10]


def decrypt_file(src, dest):
    print("[Log] Parsing original file....")
    with open(src, "rb") as fp:
        # find rights position
        fp.seek(0, os.SEEK_END)
        fp.seek(fp.tell() - 30, os.SEEK_SET)
        tail = fp.read()
        m = re.search(rb"startrights (\d+),(\d+)", tail)
        if not m:
            raise CustomException("[Error] Format error. {}".format(tail))
        # find rights
        fp.seek(int(m.group(1)), os.SEEK_SET)
        eof_offset = int(m.group(1)) - 13
        right_meta = fp.read(int(m.group(2))).decode("latin")
    # request stage 1 password
    root = ElementTree.fromstring(right_meta)
    drm_url = root.find("./protect/auth/permit/server/url").text
    file_id = root.find("./file-id").text
    password_from_file = root.find("./protect/auth/permit/password").text
    iv_from_file = root.find("./protect/auth/iv").text
    rights = root.find("./rights").text
    stripped_right_meta = re.sub(
        r"\<rights\>[\w+/=]+\</rights\>", "<rights></rights>", right_meta)

    print("[Log] Request the key from server...")
    password_from_server = request_password(drm_url, file_id)

    print("[Log] Decrypt DRM info...")
    file_key = decrypt_file_key(password_from_file,
                                password_from_server.encode("ascii"),
                                iv_from_file,
                                stripped_right_meta.encode("ascii"),
                                rights)
    print("[Log] Decrypt original file...")
    src_fp = open(src, "rb")
    temp_fp = tempfile.TemporaryFile()

    # fix pdf format
    src_fp.seek(eof_offset - 40, os.SEEK_SET)
    content = src_fp.read(40)
    m = re.search(rb'startxref\s+(\d+)\s', content)
    if not m:
        raise CustomException("[Error] Unable to find xref.")
    src_fp.seek(0, os.SEEK_SET)
    temp_fp.write(src_fp.read(int(m.group(1)) - 512))
    encryption_obj = b"<</Filter /Standard /V 4 /Length 128 /R 4 /O <1> /U <1> /P -4 /CF << /StdCF << /Type /CryptAlgorithm /CFM /AESV2 /AuthEvent /DocOpen >> >> /StrF /StdCF /StmF /StdCF>>"
    for line in src_fp:
        if b"%%EOF" in line:
            temp_fp.write(b"%%EOF")
            break
        if b"SubFilter/TTKN.PubSec.s1" in line:
            origin_len = len(line)
            line = encryption_obj + b"\n" * (origin_len - len(encryption_obj))
        temp_fp.write(line)
    src_fp.close()
    temp_fp.seek(0, os.SEEK_SET)
    out = open(dest, "wb")

    print("[Log] Writing the decrypted data into a new PDF...")
    Pdf.open(temp_fp, password=file_key.hex(), hex_password=True).save(out)
    temp_fp.close()
    out.close()
    print("[Log] Successfully decrypted!")


def main():
    parser = OptionParser(
        usage="Usage: python3 %prog -i INPUT_FILE -o OUTPUT_FILE")
    parser.add_option("-i", "--input", dest="src",
                      help="Original file name.", metavar="FILE")
    parser.add_option("-o", "--output", dest="dst",
                      help="Output file name.", metavar="FILE")
    (options, _) = parser.parse_args()
    if not options.src or not options.dst:
        parser.print_help()
        exit(0)
    if not os.path.isfile(options.src):
        print("[Error] Input file is not exist in this folder.")
        parser.print_help()
        exit(0)
    if os.path.isfile(options.dst):
        ans = input("File {} is already exist. Overwrite it? [y/N]: ".format(options.dst))
        if ans.lower() != "y":
            exit(0)

    decrypt_file(options.src, options.dst)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[Log] Suspended.")
        sys.exit(0)
    except (CustomException, Exception) as exc:
        if not isinstance(exc, CustomException):
            print("[Error] Unknown error: ", str(exc))
        else:
            print("[Error]", str(exc))
        print("-" * 64)
        traceback.print_exc()
