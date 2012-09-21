'''
Created on Sep 19, 2012

@author: cjneasbi
'''

#added $, [, ], and ~ to regex, they exist in some urls
#HTTP_REQ_REGEX = '(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s[a-zA-Z0-9/._,;()&?%=:+\-$~\[\]|@]+\sHTTP/[1-2]\.[0-9]\s'
HTTP_REQ_REGEX = '(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s\S+\sHTTP/[1-2]\.[0-9]\s'

#added the optional decimal sub-codes because of IIS 7.0 and 7.5 
#http://support.microsoft.com/kb/943891
HTTP_RESP_REGEX = 'HTTP/[1-2]\.[0-9]\s[1-5][0-9][0-9](.[0-9][0-9]?)?\s'

#http://www.w3.org/Protocols/rfc2616/rfc2616.html
#these regexes are necessary for chunked encoded response processing
CTL_REGEX = '\x00-\x19\x7f'
SEP_REGEX = '()<>@,;:\\"/\[\]?=\{\}\x20\x09'
TOKEN_REGEX = '[^' + CTL_REGEX + SEP_REGEX + ']+'

QDTEXT_REGEX = '[^"]'
QPAIR_REGEX = '\\.'
QSTR_REGEX = '("(' + QDTEXT_REGEX + '|' + QPAIR_REGEX + ')*")'

END_CHUNK_REGEX = '0(;' + TOKEN_REGEX + '( = (' + QSTR_REGEX + '|' + TOKEN_REGEX + '))?)*\r\n'