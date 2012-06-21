'''
Created on Jun 18, 2012

@author: cjneasbi
'''

from pcaptomitm import *

import sys
import os.path    

def main():
    if len(sys.argv) < 3:
        print "Usage: " + os.path.split(sys.argv[0])[1] + " <pcap_file> <output_file>"
    else:    
        http_req = extract.extract_flows(sys.argv[1])
        dump.dump_flows(http_req, sys.argv[2])

if __name__ == '__main__':
    main()