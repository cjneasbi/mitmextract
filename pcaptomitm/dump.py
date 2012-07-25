'''
Created on Jun 14, 2012

@author: cjneasbi
'''
import string, urlparse

from netlib import http 
from libmproxy import flow, proxy
from StringIO import StringIO


def parse_url(url):
    port = None
    _, netloc, path, params, query, fragment = urlparse.urlparse(url)
    if ':' in netloc:
        host, port = string.rsplit(netloc, ':', maxsplit=1)
        try:
            port = int(port)
        except ValueError:
            return None
    else:
        host = netloc

    path = urlparse.urlunparse(('', '', path, params, query, fragment))
    if not path.startswith("/"):
        path = "/" + path
    return host, port, path

def create_http_request(flowheader, reqbuf):
    sfp = StringIO(reqbuf)
    method, url, httpversion = http.parse_init_http(sfp.readline())
    host, port, path = parse_url(url)
    headers = http.read_headers(sfp)
    
    if not host:
        if not headers.get("host"):
            host = flowheader.dstip
        else:
            host = headers.get("host")[0]
    if port == None:
        port = flowheader.dport
    
    # TODO: passing None as the second arg will produce and error if "expect" is in the headers
    content = http.read_http_body_request(sfp, None, headers, httpversion, None)
    
    #content = http.read_http_body(sfp, headers, True, None)
    return flow.Request(None, httpversion, host, port, "http", \
                        method, path, headers, content, flowheader.ts)
    
def create_http_response(flowheader, respbuf, request):
    sfp = StringIO(respbuf)
    line = sfp.readline()
    if not line:
        raise proxy.ProxyError(502, "Blank server response.")
    parts = line.strip().split(" ", 2)
    if len(parts) == 2: # handle missing message gracefully
        parts.append("")
    if not len(parts) == 3:
        raise proxy.ProxyError(502, "Invalid server response: %s."%line)
    proto, code, msg = parts
    httpversion = http.parse_http_protocol(proto)
    if httpversion is None:
        raise proxy.ProxyError(502, "Invalid HTTP version: %s."%httpversion)
    try:
        code = int(code)
    except ValueError:
        raise proxy.ProxyError(502, "Invalid server response: %s."%line)
    headers = http.read_headers(sfp)
    if code >= 100 and code <= 199:
        return create_http_response(flowheader, respbuf, None)
    if request.method == "HEAD" or code == 204 or code == 304:
        content = ""
    else:
        content = http.read_http_body_response(sfp, headers, None)
    return flow.Response(request, httpversion, code, msg, headers, content, None, flowheader.ts)

def dump_flows(http_req, outfilepath):
    flows = create_flows(http_req)
    outfile = open(outfilepath,"w")
    write_flows(flows, outfile)

def write_flows(flows, outfile):
    fw = flow.FlowWriter(outfile)
    for f in flows:
        fw.add(f)

def create_flow(flowheader, tup):
    req = None
    resp = None
    
    if tup[1]:
        req = create_http_request(flowheader, tup[1])
    
    #Only want flows where there is at least a request, ignore extra
    #responses    
    if req and tup[2]:
        resp = create_http_response(flowheader, tup[2], req)
        
    if req:
        f = flow.Flow(req)
        if resp:
            f.response = resp
        return f
    else:
        return None;

def create_flows(http_req):
    flows = list()    
    for fh in sorted(http_req.keys(), key=lambda x: x.ts):
        for tup in http_req[fh]:
            f = create_flow(fh, tup)
            if f:
                flows.append(create_flow(fh, tup))
    return flows