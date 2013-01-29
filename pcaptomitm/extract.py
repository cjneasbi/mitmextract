
import sys
import re
import nids

from . import regex

DEBUG = False

#initialize on every call of extract_flows
ts = None # request timestamp
requestdata = None # buffer for requests from open connections
responsedata = None # buffer for responses from open connections
requestcounter = None
http_req = None # contains data from closed connections

NIDS_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class FlowHeader(object):
    def __init__(self, ts_request_start, ts_request_finish, ts_response_start, 
                 ts_response_finish, srcip, sport, dstip, dport):
        self.ts_request_start = ts_request_start
        self.ts_request_finish = ts_request_finish
        self.ts_response_start = ts_response_start
        self.ts_response_finish = ts_response_finish
        self.srcip = srcip
        self.sport = sport
        self.dstip = dstip
        self.dport = dport
        
    def __eq__(self, other):
        return (self.ts_request_start, self.ts_request_finish, 
                self.ts_response_start, self.ts_response_finish, 
                self.srcip, self.sport, self.dstip, self.dport) == \
            (other.ts_request_start, other.ts_request_finish, 
             other.ts_response_start, other.ts_response_finish,
             other.srcip, other.sport, other.dstip, other.dport)

    def __hash__(self):
        return hash((self.ts_request_start, self.ts_request_finish, 
                self.ts_response_start, self.ts_response_finish, 
                self.srcip, self.sport, self.dstip, self.dport))
    
    def __repr__(self):
        return ("FlowHeader(ts_request_start=%r,ts_request_finish=%r,ts_response_start=%r"
                ",ts_response_finish=%r,srcip=%r,sport=%r,dstip=%r,dport=%r)") % \
            (self.ts_request_start, self.ts_request_finish, 
                self.ts_response_start, self.ts_response_finish, 
                self.srcip, self.sport, self.dstip, self.dport)
    
    def __str__(self):
        return self.__repr__()

#http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
#finds the ending index of chucked response starting at the index start
def find_chunk_end(h, start):    
    matches = re.finditer(regex.END_CHUNK_REGEX, responsedata[h])
    end_size_line = -1
    for m in matches:
        if m.start() > start:
            #we subtract 2 because if there is no trailer after the
            #last chuck the first CRLF of the ending double CRLF is
            #the CRLF at the end of the regex 
            end_size_line = m.end() - 2
            break
    
    if end_size_line != -1:    
        matches = re.finditer('\r\n\r\n', responsedata[h])
        for m in matches:
            if m.start() >= end_size_line:
                return m.end()  
    
    return None

def get_response_headers(h, start):
    return get_headers(responsedata, h, start)

def get_request_headers(h, start):
    return get_headers(requestdata, h, start)

def get_headers(buf, h, start):
    header_start = None
    header_end = None
    matches = re.finditer('\r\n\r\n', responsedata[h])
    for m in matches:
        if m.start() > start:
            header_end = m.end()
            break
        
    matches = re.finditer('\r\n', responsedata[h])
    for m in matches:
        if m.start() > start:
            header_start = m.end()
            break
        
    if header_start is not None and header_end is not None:
        return buf[h][header_start:header_end]
        
    return None
    
def split_responses(h):
    matches = re.finditer(regex.HTTP_RESP_REGEX, responsedata[h])
    responses = list()
    start = -1
    for m in matches:
        end = -1
        if start != -1 and start < m.start():
            headers = get_response_headers(h, start)                
            if "Transfer-Encoding: chunked" in headers:
                end = find_chunk_end(h, start)
            else :
                end = m.start()
                           
            responses.append(responsedata[h][start : end])
        else:
            end = m.start()
        start = end
        
    responses.append(responsedata[h][start:])
    return responses

def split_requests(h):
    matches = re.finditer(regex.HTTP_REQ_REGEX, requestdata[h])
    requests = list()
    start = -1
    for m in matches:
        if start != -1:
            requests.append(requestdata[h][start : m.start()])
        start = m.start()
        
    requests.append(requestdata[h][start:])
    return requests


def is_http_response(data):
    m = re.search(regex.HTTP_RESP_REGEX, data)
    if m:
        if m.start() == 0:
            return True

    return False


def is_http_request(data):
    m = re.search(regex.HTTP_REQ_REGEX, data)
    if m:
        if m.start() == 0:
            return True

    return False

def num_requests(h): 
    return len(re.findall(regex.HTTP_REQ_REGEX, requestdata[h]))

def num_responses(h):
    matches = re.finditer(regex.HTTP_RESP_REGEX, responsedata[h])
    resp_count = 0
    start = -1
    for m in matches:
        end = -1
        if start != -1 and start < m.start():
            headers = get_response_headers(h, start)                
            if "Transfer-Encoding: chunked" in headers:
                end = find_chunk_end(h, start)
            else:
                end = m.start()
                           
            resp_count += 1
        else:
            end = m.start()
        start = end
        
    if len(responsedata[h][start:].strip()) > 0:
        resp_count += 1
        
    return resp_count 

# returns a list of tuple, each tuple contains (count, request, response)
def add_reconstructed_flow(h):
    retval = list()
    requests = list()
    responses = list()
    
    if num_requests(h) > 1:
        requests = split_requests(h)
    else:
        requests.append(requestdata[h])

    if num_responses(h) > 1:
        responses = split_responses(h)
    else:
        responses.append(responsedata[h])
        
    maxlen = 0
    if len(requests) > len(responses):
        maxlen = len(requests)
    else:
        maxlen = len(responses)
        
    if DEBUG and len(requests) != len(responses):
        print "Unequal number of requests and responses. " + str(h)
        print(str(len(requests)) + " " + str(len(responses)) + "\n")
    
    for i in range(maxlen):
        countval = None
        reqval = None
        respval = None
        
        if i < len(requests) and len(requests[i].strip()) > 0 and is_http_request(requests[i]):
            reqval = requests[i]
            
        if i < len(responses) and len(responses[i].strip()) > 0 and is_http_response(responses[i]):
            respval = responses[i]
        
        if reqval or respval:
            countval = requestcounter[h]
            requestcounter[h] = requestcounter[h] + 1            
        
        if countval != None:
            if DEBUG:
                print "Appending request " + str(countval) + " to " + str(h)    
            retval.append((countval, reqval, respval))
    
    requestdata[h] = ''
    responsedata[h] = ''

    if DEBUG:
        print "Tuples in list for " + str(h) + " = " + str(len(retval))
    return retval



def handle_tcp_stream(tcp):
    global DEBUG
    # print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new tcp flow
        ((srcip, sport), (dstip, dport)) = tcp.addr
        h = (srcip, sport, dstip, dport)
        #(req_start, req_stop, resp_start, resp_stop)
        ts[h] = [nids.get_pkt_ts(), 0, 0 ,0]

        requestcounter[h] = 0
        requestdata[h] = ''
        responsedata[h] = ''
         
        if DEBUG: print "Reconstructing TCP flow:", tcp.addr
        tcp.client.collect = 1 # collects server -> client data
        tcp.server.collect = 1 # collects client -> server data

    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)
        ((srcip, sport), (dstip, dport)) = tcp.addr
        h = (srcip, sport, dstip, dport)
        
        if requestdata.has_key(h):
            client2server_data = tcp.server.data[tcp.server.count-tcp.server.count_new:tcp.server.count]
            server2client_data = tcp.client.data[tcp.client.count-tcp.client.count_new:tcp.client.count]
            
            #this if statement is necessary to ensure proper ordering of request/response pairs in the output
            if is_http_request(client2server_data): 
                                
                if len(requestdata[h]) > 0:
                    if DEBUG: print "Added request/response..."
                    k = FlowHeader(ts[h][0], ts[h][1], ts[h][2], ts[h][3], h[0], h[1], h[2], h[3])
                    http_req[k] = add_reconstructed_flow(h)
                    
                ts[h] = [nids.get_pkt_ts(), 0, 0 ,0]
                 
            if len(client2server_data) > 0:
                #sets the start timestamp for request
                if(requestdata[h] == ''):
                    ts[h][0] = nids.get_pkt_ts()
                requestdata[h] = requestdata[h] + client2server_data
                #sets the end timestamp for request
                ts[h][1] = nids.get_pkt_ts()
                
            if len(server2client_data) > 0:
                #sets the start timestamp for response
                if(responsedata[h] == ''):
                    ts[h][2] = nids.get_pkt_ts()
                responsedata[h] = responsedata[h] + server2client_data
                #sets the end timestamp for response
                ts[h][3] = nids.get_pkt_ts()

    elif tcp.nids_state in NIDS_END_STATES:
        ((srcip, sport), (dstip, dport)) = tcp.addr
        if DEBUG: print "End of flow:", tcp.addr

        h = (srcip, sport, dstip, dport)        
        if requestdata.has_key(h) and is_http_request(requestdata[h]) and is_http_response(responsedata[h]):
            k = FlowHeader(ts[h][0], ts[h][1], ts[h][2], ts[h][3], h[0], h[1], h[2], h[3])
            http_req[k] = add_reconstructed_flow(h)
        else: 
            if DEBUG:
                print "Failed to add flow"
                print str(h)
                print "has_key? " + str(requestdata.has_key(h))
                print "is_http_request? " + str(is_http_request(requestdata[h]))
                print "is_http_response? " + str(is_http_response(responsedata[h]))
            
        del ts[h]
        del requestdata[h]
        del responsedata[h]
        del requestcounter[h]
    
# adds the remaining open connections to the http_req dictionary 
def finalize_http_flows():
    for h in requestdata.keys():
        finalize_http_flow_header(ts[h])
        k = FlowHeader(ts[h][0], ts[h][1], ts[h][2], ts[h][3], h[0], h[1], h[2], h[3])
        if DEBUG:
            print "Finalizing flow", k
        http_req[k] = add_reconstructed_flow(h)
    
         
    for h in http_req.keys():
        if len(http_req[h]) < 1:
            del http_req[h]
            
    if DEBUG: print "Num of flows " + str(len(http_req.keys()))

# sets the empty timestamp values for the remaining open connections    
def finalize_http_flow_header(header):
    for i in range(len(header)):
        if header[i] == 0:
            header[i] = nids.get_pkt_ts()
        

# prints flow headers in timestamp order
def print_flows(http_req):
    for fh in sorted(http_req.keys(), key=lambda x: x.ts):
        print str(fh) + " " + str(len(http_req[fh]))
#        if DEBUG:
#            for tup in http_req[fh]:
#                print tup

# extracts the http flows from a pcap file
# returns a dictionary of the reconstructed flows, keys are FlowHeader objects
# values are lists of tuples of the form (count, request, response)        
def extract_flows(pcap_file):
    global ts, requestdata, responsedata, requestcounter, http_req
    ts, requestdata, responsedata, requestcounter, http_req = \
        dict([]), dict([]), dict([]), dict([]), dict([])
    
    nids.param("tcp_workarounds", 1)
    nids.param("pcap_filter", "tcp")        # bpf restrict to TCP only, note
    nids.param("scan_num_hosts", 0)         # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming

    nids.param("filename", pcap_file)
    nids.init()
    nids.register_tcp(handle_tcp_stream)
    # print "pid", os.getpid()

    if DEBUG: print "Reading from pcap file:", pcap_file

    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error: ", pcap_file + " ",  e
    except KeyboardInterrupt:
        print "Control C!"
        sys.exit(0)
    except Exception, e:
        print "Exception (runtime error in user callback?): ", pcap_file + " ", e

    finalize_http_flows()
    if DEBUG: print "Done!\n"
    return http_req
    
    