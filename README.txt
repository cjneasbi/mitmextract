**mitmextract** extracts the http flows from a pcap file and 
converts them into a **mitmproxy** flow dump.

Download
--------

Source is hosted on github: 

`github.com/cjneasbi/mitmextract`_


Requirements
------------

* Python_ 2.7.x
* libmproxy_ 0.8
* netlib_ 0.8
* pynids_ 0.6.1

**mitmextract** has only been tested on Linux but should work with
any platform supporting the above requirements.

Usage
-----

Usage: mitmextract.py [options] <pcap_file> <output_file>

Options:
  -h, --help            show this help message and exit
  -d, --debug           Display debugging output.
  -f FILTERS, --filter=FILTERS
                        Filter flows whose request headers contain a specified
                        value.  Filters must be constructed with the format
                        <header-field>:<header-field-value>.  Multiple filters
                        may be specified.

Caveats
-------

* Only extracts IPv4 HTTP flows.
