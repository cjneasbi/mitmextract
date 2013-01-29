'''
Created on Jun 14, 2012

@author: cjneasbi
'''
import string, urlparse, traceback

from netlib import http 
from libmproxy import flow
from StringIO import StringIO

DEBUG = False

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
            if ':' in host:
                host = string.rsplit(host, ':', maxsplit=1)[0]
            
    if port == None:
        port = flowheader.dport
    
    # TODO: passing None as the second arg will produce and error if "expect" is in the headers
    content = http.read_http_body_request(sfp, None, headers, httpversion, None)
        
    #content = http.read_http_body(sfp, headers, True, None)
    return flow.Request(None, httpversion, host, port, "http", \
                        method, path, headers, content, flowheader.ts_request_start,
                        flowheader.ts_request_finish)

def create_http_response(flowheader, respbuf, request):
    sfp = StringIO(respbuf)
    httpversion, code, msg, headers, content = http.read_response(
        sfp, request.method, None)
    return flow.Response(request, httpversion, code, msg, headers, 
        content, None, flowheader.ts_response_start, flowheader.ts_response_finish)

def dump_flows(http_req, outfilepath):
    flows = create_flows(http_req)
    outfile = open(outfilepath,"w")
    write_flows(flows, outfile)
                
def filter_flows_by_header(flows, header, value):
    for f in flows:
        cnttype = f.request.headers.get(header)
        if cnttype is not None and value in cnttype:
            flows.remove(f)
            if DEBUG:
                print "Filtered flow with " + header + " = " + value, f.request._get_state()

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
    
    #Each flow must have a request and a response    
    if req is not None and resp is not None:
        f = flow.Flow(req)
        f.response = resp
        return f
    else:
        return None;

def create_flows(http_req):
    flows = list()    
    for fh in sorted(http_req.keys(), key=lambda x: x.ts_request_start):
        for tup in http_req[fh]:
            try:
                f = create_flow(fh, tup)
                if f is not None:
                    flows.append(f)
            except Exception:
                print traceback.format_exc(), fh
    return flows