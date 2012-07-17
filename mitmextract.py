'''
Created on Jun 18, 2012

@author: cjneasbi
'''

from pcaptomitm import *
from optparse import OptionParser    

def main():
    parser = config_options()
    options, args = parser.parse_args()
    
    if options.debug:
        extract.DEBUG = True
    
    if len(args) < 2:
        parser.print_help()
    else:    
        http_req = extract.extract_flows(args[0])
        dump.dump_flows(http_req, args[1])

def config_options():
        parser = OptionParser(
                usage = "%prog [options] <pcap_file> <output_file>",
            )
        parser.add_option(
            "-d", "--debug",
            action="store_true", dest="debug", default=False,
            help="Display debugging output."
        )
        
        return parser

if __name__ == '__main__':
    main()