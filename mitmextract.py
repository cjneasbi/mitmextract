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
        dump.DEBUG = True
        
    if len(args) < 2:
        parser.print_help()
    else:   
        http_req = extract.extract_flows(args[0])
        flows = dump.create_flows(http_req)
        
        if len(options.filters) > 0:
            for f in options.filters:
                filt = f.strip().split(":")
                if len(filt) == 2:
                    dump.filter_flows_by_header(flows, filt[0], filt[1])
        
        dump.write_flows(flows, open(args[1], "w"))

def config_options():
        parser = OptionParser(
                usage = "%prog [options] <pcap_file> <output_file>",
            )
        parser.add_option(
            "-d", "--debug",
            action="store_true", dest="debug", default=False,
            help="Display debugging output."
        )
        parser.add_option(
            "-f", "--filter",
            action="append", dest="filters", default=list(),
            help="Filter flows whose request headers contain a specified value.  " +  \
                "Filters must be constructed with the format <header-field>:<header-field-value>.  " + \
                "Multiple filters may be specified."  
        )
        
        return parser

if __name__ == '__main__':
    main()