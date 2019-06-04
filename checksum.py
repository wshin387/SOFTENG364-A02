# -*- coding: utf-8 -*-

def hextet_complement(x):
    """
     compute the one's complement of a Python int regarded as a
    fixed-width hextet (16 bits, two bytes/octets, four nibbles).
    :param x: int
    :return: the hextet complement of x
    """
    return ~x & 0xffff


def internet_checksum(data, total=0x0):
    '''
    Internet Checksum of a bytes array.
    Further reading:
    1. https://tools.ietf.org/html/rfc1071
    2. http://www.netfor2.com/checksum.html
    '''
    carry =0
    for i in range(0,len(data),2):
        #odd data length
        if i+1 >= len(data):
            wrap=data[i]
            carry=wrap+total
            total= (carry & 0xFFFF) + (carry >> 16)

        else:
            wrap = (data[i] << 8) + data[i+1]
            carry = wrap + total
            total = (carry & 0xFFFF) + (carry >> 16)
    return hextet_complement(total)


