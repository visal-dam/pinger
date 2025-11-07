from socket import *
import struct
from time import *
import select
from datetime import *

ICMP_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
ICMP_socket.setblocking(False)
def bin_splitter(data, start, end): #returns part of a binary string
    storage = ''.join(bin(int(data[i]))[2:] for i in range(start, end))
    return storage

def bin_cks_adder(a, b): #adds parts of a string with another part (parts are param)
    sum = bin(int(a, 2) + int(b, 2))
    if len(sum[2:]) > len(a): #if carry over
        wrap_bit = sum[2] #takes left-most bit, 0b'X'
        sum = sum[3:] #gets rid of '0bX'
        result = bin(int(sum, 2) + int(wrap_bit))
        return result[2:] #doesn't matter if left-most == 0
    return sum[2:] #RETURNS STRING

def denTObin(den, size): #converts from denary to binary
    return(bin(den)[2:].zfill(size)) #skips "0b"
def checksum_adder(d, start, end): #returns checksum (add & 1') for any given length | 16
    div_index = int(len(d)/16)
    first = bin_splitter(d, start, end)
    next = bin_splitter(d, start + 16, end + 16)
    this_sum = bin_cks_adder(first, next)
    for x in range(0, div_index-2):
        start += 16
        end += 16
        next = bin_splitter(d, start + 16, end + 16)
        this_sum = bin_cks_adder(this_sum, next)
    result = ''
    for y in this_sum.zfill(16):
        if y == '1':
            result += '0'
        else:
            result += '1'
    return result

def ping_stats(data, rec_time): #displays bytes received, source (target init), TTL, and rtt (in Python)
    #MAIN DATA
    IP_DHL = struct.unpack_from('b', data, 0) #less than max
    IP_DHL = str(IP_DHL)[1:3]
    IP_DHL = bin(int(IP_DHL, 10))[2:].zfill(8)
    DHL = int(IP_DHL[4:8], 2) #5
    DHL = DHL * 4 #20 bytes

    len_total = int(struct.unpack_from('b', data, 3)[0])
    data_bytes = len_total - DHL - 8 #icmp header = 8 bytes long; data_bytes

    ip_part = ''
    i = 12
    for x in range(0, 4):
        ip_part += str(int(struct.unpack_from('B', data, i)[0])) + '.'
        i += 1
    src_ip = ip_part[:-1]

    ttl = struct.unpack_from('B', data, 8)[0]

    print("Reply from: '" + src_ip + "'; Data: " + str(data_bytes) + " bytes; ", "TTL: "+ str(ttl) + "ms; ", "rtt: ", str(rec_time) + "s")

destname = '8.8.8.8'
destIP = gethostbyname(destname)
#destIP = '1.0.0.1'

for x in range (1, 5): #main
    icmp_type = bin(8)[2:].zfill(8) #binary form for calc
    icmp_code = bin(0)[2:].zfill(8) #same
    icmp_data = 1111 #int dummy data
    icmp_data_BIN = denTObin(icmp_data, 64) #binary form for calc
    #combines all values
    d = icmp_type + icmp_code + '0000000000000000' + bin(1)[2:].zfill(16) + bin(x)[2:].zfill(16) + icmp_data_BIN #one long binary string
    #checksum
    icmp_checksum = checksum_adder(d, 0, 16) #checksum operation
    icmp_checksum = struct.pack('>H',int(icmp_checksum,2)) #packs
    #constructs header and packet
    icmp_header = struct.pack('bb', 8, 0) + icmp_checksum + struct.pack('>hh', 1, x)
    icmp_packet = icmp_header + struct.pack('>h', icmp_data) #adds data
    #pinging
    print("Pinging '" + destIP + "'....")
    ICMP_socket.sendto(icmp_packet, (destIP, 0))
    sent_time = datetime.now()
    #selecting from socket
    inputs = [ICMP_socket] #socket to be checked
    timeout = float(4) #4s
    readable, writable, exceptional = select.select(inputs, [], [], timeout) #checks I/O completeness
    if readable: #if activity detected
        rec_time = datetime.now() - sent_time
        serverReply = ICMP_socket.recvfrom(2048)
        ping_stats(serverReply[0], str(rec_time)[6:])  # [0] gets first part, rest are 'destIP, 0' (look at socket)
    else: #timeout
        print("Request time exceeded")
    sleep(1) #1s delay before next ping

ICMP_socket.close() #close socket