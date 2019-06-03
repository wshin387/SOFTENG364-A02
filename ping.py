# -*- coding: utf-8 -*-
import os
import sys
import socket
import struct
import time

import collections
from checksum import internet_checksum

assert 3 <= sys.version_info[0], 'Requires Python 3'

# For readability in time conversions
MILLISEC_PER_SEC = 1000.0

# Selects the right-most 16 bits
RIGHT_HEXTET = 0xffff

# Size in bits of buffer in which socket data is received
BUFFER_SIZE = 2 << 5

# A port number is required for socket.socket, even through port
# numbers are unused by ICMP. We use a legal (i.e. strictly positive)
# port number, just to be safe.
ICMP_PORT_PLACEHOLDER = 1
ICMP_HEADER_LENGTH = 28
ICMP_STRUCT_FIELDS = "BBHHH"  # for use with struct.pack/unpack

MILLISEC_PER_SEC = 1000


#
# TODO: Define ChecksumError class
#
class ChecksumError(Exception):
    # Raised when checksum values do not match
    pass

# Note that TimeoutError already exists in the Standard Library
#class TimeoutError(PingError):
#    pass


# See IETF RFC 792: https://tools.ietf.org/html/rfc792
# NB: The order of the fields *is* significant
ICMPMessage = collections.namedtuple('ICMPMessage',
                                  ['type', 'code', 'checksum',
                                   'identifier', 'sequence_number'])
# For ICMP type field:
# See https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
#     http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
ICMPTypeCode = collections.namedtuple('ICMPTypeCode', ['type', 'code'])
ECHO_REQUEST = ICMPTypeCode(8, 0)
ECHO_REPLY = ICMPTypeCode(0, 0)


def this_instant():
	# TODO: Decide which of the following values to return here:
	# time.clock(), time.perf_counter(), time.process_time()
    return time.perf_counter()
    


def ping(client_socket, dest_host, client_id, seq_no=0):
    """
   Sends echo request, receives response, and returns RTT.
    """

    def icmp_header(host_checksum):
        message = ICMPMessage(
                    type=ECHO_REQUEST.type,  # TODO: Use appropriate argument here
                    code=ECHO_REQUEST.code,  # TODO: Use appropriate argument here
                    checksum=host_checksum,
                    identifier=client_id,
                    sequence_number=seq_no)
        return struct.pack(ICMP_STRUCT_FIELDS, *message)

	# TODO: Please study these lines carefully,
	#       noting that "icmp_pack()" (defined above) is called *twice*
    icmp_payload = struct.pack('d', this_instant())  # double-precision float
    icmp_packet_without_checksum = icmp_header(0) + icmp_payload
    checksum = internet_checksum(icmp_packet_without_checksum)
    icmp_packet = icmp_header(checksum) + icmp_payload

    #
    # TODO: Please note that that "icmp_packet" is the
    #       payload that we'll send through for our INET raw socket
    #

    # Note: socket.gethostbyname() returns the host name
    # unchanged if it is already in IPv4 address format.
    dest_host = socket.gethostbyname(dest_host)
    #.
	# TODO:
	# 1. Call sendto() on socket to send packet to destination host
    
    client_socket.sendto(icmp_packet,(dest_host,ICMP_PORT_PLACEHOLDER))
    # 2. Call recvfrom() on socket to receive datagram
    try:
        dgram,address = client_socket.recvfrom(BUFFER_SIZE)
    except socket.timeout as error:
        raise TimeoutError()
    
    #    (Note: A time-out exception might be raised here).
    # 2. Store this_instant() at which datagram was received
    time_received = this_instant()
	# 3. Extract ICMP packet from datagram i.e. drop IP header (20 bytes)
	#     e.g. "icmp_packet = datagram[20:]"
    icmp_packet = dgram[20:]
	# 4. Compute checksum on ICMP response packet (header and payload);
	#     this will hopefully come to zero
    
    # get checksum fields
    checksum = int.from_bytes(icmp_packet[3:1:-1], byteorder='big')
    # zero out checksum fields (third and fourth byte) on response
    icmp_packet_copy = icmp_packet[:2] + icmp_packet[4:]
    # verify checksum
    value = internet_checksum(icmp_packet_copy, checksum)
    if value != 0:
        raise ChecksumError()
    
	# 5. Raise exception if checksum is nonzero
	# 6. Extract ICMP response header from ICMP packet (8 bytes) and
	#     unpack binary response data to obtain ICMPMessage "response"
	#     that we'll return with the round-trip time (Step 9, below);
	#     notice that this namedstruct is printed in the sample
	#     command line output given in the assignment description.
	#     e.g. "Reply from 151.101.0.223 in 5ms: ICMPMessage(type=0, code=0, checksum=48791, identifier=33540, sequence_number=0)"
    icmp_header = icmp_packet[:8]
    response = ICMPMessage(*struct.unpack(ICMP_STRUCT_FIELDS,icmp_header))
    
    # 7. Extract ICMP response payload (remaining bytes) and unpack
	#     binary data to recover "time sent"
    icmp_payload = icmp_packet[8:]
    bytes_in_double = struct.calcsize('d')
    time_sent = struct.unpack('d', icmp_payload[0:bytes_in_double])[0]
    round_trip_time = time_received - time_sent
    return round(round_trip_time*MILLISEC_PER_SEC),response
    
    
	# 8. Compute round-trip time from "time sent"
	# 9. Return "(round-trip time in milliseconds, response)"
	#
    # If things go wrong
    # ==================
    # You might like to check ("assert") that:
    # 1. Type field of ICMP response header is ICMP echo reply type
    # 2. Code field of ICMP response header is ICMP echo reply code
    # 3. Identifier field of ICMP response header is client_id
    # 4. len() of ICMP response payload is struct.calcsize('d')
    #

def verbose_ping(host, timeout=2.0, count=4, log=print):
    """
    Send ping and print session details to command prompt.
    """
    try:
        host_ip = socket.gethostbyname(host)
    except OSError as error:
        log(error)
        log('Could not find host {}.'.format(host))
        log('Please check name and try again.')
        return

    #
	# TODO: Print suitable heading
	#       e.g. log("Contacting {} with {} bytes of data ".format(...))
    #
    log("Contacting {} with {} bytes of data ".format(host,36))

    round_trip_times = []

    for seq_no in range(count):
        try:
            #
			# TODO: Open socket using "with" statement
			#
            with socket.socket(family=socket.AF_INET,
                               type=socket.SOCK_RAW, # <=="raw socket"
                               proto=socket.getprotobyname('icmp')) as client_socket:
                client_socket.settimeout(timeout/MILLISEC_PER_SEC)
			# TODO: set time-out duration (in seconds) on socket
			#

                # "The Identifier and Sequence Number can be used by the
                # client to match the reply with the request that caused the
                # reply. In practice, most Linux systems use a unique
                # identifier for every ping process, and sequence number is
                # an increasing number within that process. Windows uses a
                # fixed identifier, which varies between Windows versions,
                # and a sequence number that is only reset at boot time."
                # -- https://en.wikipedia.org/wiki/Ping_(networking_utility)
                client_id = os.getpid() & RIGHT_HEXTET

                delay, response = ping(client_socket,
                                   host,
                                   client_id=client_id,
                                   seq_no=seq_no)

            log("Reply from {:s} in {}ms: {}".format(host_ip, delay, response))

			#
            # TODO: Append "delay" to round_trip_times
			#
            round_trip_times.append(delay)

		# TODO:
        # catch time-out error:
        #     handle time-out error i.e. log(...)
        except TimeoutError as error:
            log("Time out error has been caught after {}ms".format(round(timeout)))
		# TODO:
        # catch check-sum error
        #     handle checksum-error i.e. log(...)
        except ChecksumError as error:
            log("ChecksumError has been caught")

        except OSError as error:
            log("OS error: {}. Please check name.".format(error.strerror))
            if isinstance(error, PermissionError):
                # Display the likely explanation for
                # TCP Socket Error Code "1 = Operation not permitted":
                log("NB: On some sytems, ICMP messages can"
                    " only be sent from processes running as root.")
            break

	#
	# TODO: Print packet statistics header
	# TODO: Compute & print packet statistics
	#       i.e. "how many packets received and lost?"
    received = len(round_trip_times)
    lost_packets = count - received
    log('Ping Statistics for {}:'.format(host_ip))
    log('Packets: Sent = {}, Received = {}, Lost = {} ({}% loss)'.format(count,received,lost_packets,(count-received)/count*100))

    # TODO: "if received more than 0 packets":
	#    TODO: Compute & print statistics on round-trip times
	#          i.e. Minimum, Maximum, Average
	#
    if len(round_trip_times) > 0:
        count=0
        stats = [min(round_trip_times),max(round_trip_times),0]
        for time in round_trip_times:
            stats[2] += time
        stats[2] = stats[2]//len(round_trip_times)
        log('Approximate round trip times')
        log('Minimum = {}ms, Maximum = {}ms, Average = {}ms'.format(stats[0],stats[1],stats[2]))
    if len(round_trip_times) == 0:
        log('No round trip time data')
        
    
    

if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser(description='Test a host.')
    parser.add_argument('-w', '--timeout',
                        metavar='timeout',  # TODO: Specify this argument
                        type=int,
                        default=1000,  # TODO: Specify this argument
                        help='Timeout to wait for each reply (milliseconds).')
    parser.add_argument('-c', '--count',
                        metavar='num',
                        type=int,  # TODO: Specify this argument
                        default=4,
                        help='Number of echo requests to send')  # TODO: Specify this argument
    parser.add_argument('hosts',
                        metavar='host',
                        type=str,
                        nargs='+',
                        help='URL or IPv4 address of target host(s)')  # TODO: Specify this argument
    args = parser.parse_args()

    for host in args.hosts:
        verbose_ping(host, timeout=args.timeout, count=args.count)
