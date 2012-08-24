
import sys
import re
import nids

DEBUG = False

#initialize on every call of extract_flows
ts = None # request timestamp
requestdata = None # buffer for requests from open connections
responsedata = None # buffer for responses from open connections
requestcounter = None
http_req = None # contains data from closed connections

#added $, [, ], and ~ to regex, they exist in some urls
#HTTP_REQ_REGEX = '(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s[a-zA-Z0-9/._,;()&?%=:+\-$~\[\]|@]+\sHTTP/[1-2]\.[0-9]\s'
HTTP_REQ_REGEX = '(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s\S+\sHTTP/[1-2]\.[0-9]\s'

#added the optional decimal sub-codes because of IIS 7.0 and 7.5 
#http://support.microsoft.com/kb/943891
HTTP_RESP_REGEX = 'HTTP/[1-2]\.[0-9]\s[1-5][0-9][0-9](.[0-9][0-9]?)?\s'
NIDS_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class FlowHeader(object):
    def __init__(self, ts, srcip, sport, dstip, dport):
        self.ts = ts
        self.srcip = srcip
        self.sport = sport
        self.dstip = dstip
        self.dport = dport
        
    def __eq__(self, other):
        return (self.ts, self.srcip, self.sport, self.dstip, self.dport) == \
            (other.ts, other.srcip, other.sport, other.dstip, other.dport)

    def __hash__(self):
        return hash((self.ts, self.srcip, self.sport, self.dstip, self.dport))
    
    def __repr__(self):
        return "FlowHeader(ts=%r,srcip=%r,sport=%r,dstip=%r,dport=%r)" % \
            (self.ts,self.srcip,self.sport,self.dstip,self.dport)
    
    def __str__(self):
        return self.__repr__()

        
        
def split_requests(h):
    matches = re.finditer(HTTP_REQ_REGEX, requestdata[h])
    requests = list()
    start = -1
    for m in matches:
        if start != -1:
            requests.append(requestdata[h][start : m.start()])
        start = m.start()
        
    requests.append(requestdata[h][start:])
    return requests

def split_responses(h):
    matches = re.finditer(HTTP_RESP_REGEX, responsedata[h])
    responses = list()
    start = -1
    for m in matches:
        if start != -1:
            responses.append(responsedata[h][start : m.start()])
        start = m.start()
        
    responses.append(responsedata[h][start:])
    return responses


def is_http_response(data):
    m = re.search(HTTP_RESP_REGEX, data)
    if m:
        if m.start() == 0:
            return True

    return False


def is_http_request(data):
    m = re.search(HTTP_REQ_REGEX, data)
    if m:
        if m.start() == 0:
            return True

    return False

def num_requests(h): 
    return len(re.findall(HTTP_REQ_REGEX, requestdata[h]))

def num_responses(h):
    return len(re.findall(HTTP_RESP_REGEX, responsedata[h])) 

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
        ts[h] = nids.get_pkt_ts()

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
                    k = FlowHeader(ts[h], h[0], h[1], h[2], h[3])
                    http_req[k] = add_reconstructed_flow(h)
                    
                ts[h] = nids.get_pkt_ts() 
                 
            if len(client2server_data) > 0:
                requestdata[h] = requestdata[h] + client2server_data
                
            if len(server2client_data) > 0:
                responsedata[h] = responsedata[h] + server2client_data

    elif tcp.nids_state in NIDS_END_STATES:
        ((srcip, sport), (dstip, dport)) = tcp.addr
        if DEBUG: print "End of flow:", tcp.addr

        h = (srcip, sport, dstip, dport)        
        if requestdata.has_key(h) and is_http_request(requestdata[h]) and is_http_response(responsedata[h]):
            k = FlowHeader(ts[h], h[0], h[1], h[2], h[3])
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
        k = FlowHeader(ts[h], h[0], h[1], h[2], h[3])
        http_req[k] = add_reconstructed_flow(h)
    
         
    for h in http_req.keys():
        if len(http_req[h]) < 1:
            del http_req[h]
            
    if DEBUG: print "Num of flows " + str(len(http_req.keys()))
        

# prints flow headers in timestamp order
def print_flows(http_req):
    for fh in sorted(http_req.keys(), key=lambda x: x.ts):
        print str(fh) + " " +str(len(http_req[fh]))

# extracts the http flows from a pcap file
# returns a dictionary of the reconstructed flows, keys are FlowHeader objects
# values are lists of tuples of the form (count, request, response)        
def extract_flows(pcap_file):
    global ts, requestdata, responsedata, requestcounter, http_req
    ts, requestdata, responsedata, requestcounter, http_req = \
        dict([]), dict([]), dict([]), dict([]), dict([])
    
    
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
    
    