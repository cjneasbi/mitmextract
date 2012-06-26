**mitmextract** extracts the http flows from a pcap file and 
converts them into a **mitmproxy** flow dump.

Download
--------

Source is hosted on github: 

`github.com/cjneasbi/mitmextract`_


Requirements
------------

* Python_ 2.7.x.
* libmproxy_ 0.9 or newer.
* netlib_
* pynids_ 0.6.1

**mitmextract** has only been tested on Linux but should work with
any platform supporting the above requirements.

Caveats
-------

* Only extracts HTTP flows, there is currently no support for HTTPS.
* Only extracts IPv4 flows.
