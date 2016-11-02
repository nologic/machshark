import json
import struct
import binascii
import pprint
import sys

def parseUINT32(data):
    return struct.unpack('<I', data)[0]

def parseUINT32(data):
    return struct.unpack('<I', data)[0]

def parseFloat32(data):
    return struct.unpack('<f', data)[0]

# typedef struct
# {
#       mach_msg_bits_t                     msgh_bits;
#       mach_msg_size_t                     msgh_size;
#       mach_port_t                  msgh_remote_port;
#       mach_port_t                   msgh_local_port;
#       mach_msg_size_t                 msgh_reserved;
#       mach_msg_id_t                         msgh_id;
# } mach_msg_header_t;
# 13001100 58000000 0b150000 00000000 47a70000 00000010
def parseMsgHeader(msg):
    return {
        'msgh_bits': parseMsgHeader_bits(parseUINT32(msg[0:4])),
        'msgh_size': parseUINT32(msg[4:8]),
        'msgh_remote_port': hex(parseUINT32(msg[8:12])),
        'msgh_local_port': hex(parseUINT32(msg[12:16])),
        'msgh_reserved': parseUINT32(msg[16:20]),
        'msgh_id': parseUINT32(msg[20:24]),
        'z_chunk': binascii.hexlify(msg[0:24]),
        '_payload': msg[24:]
    }

def parseMsgHeader_bits(bits):
    return {
        'MACH_MSGH_BITS_REMOTE_MASK': hex(0x000000FF & bits),
        'MACH_MSGH_BITS_LOCAL_MASK':  hex( (0x0000ff00 & bits) >> 8),
        'MACH_MSGH_BITS_COMPLEX':     hex( (0x80000000 & bits) >> 31),
        'value' : hex(bits)
    }

# http://blog.wuntee.sexy/
def parseCPXHeader(msg):
    return {
        'magic': msg[0:4],
        'version': parseUINT32(msg[4:8]),
        'type': parseUINT32(msg[8:12]),
        'size': parseUINT32(msg[12:16]),
        'num_entries': parseUINT32(msg[16:20])
    }

def parseCPXItems(hdr, msg):
    nll = msg.index('\x00')

    return {
        'key': msg[0:nll],
        'type': parseUINT32(msg[nll+1:nll+5]),
        '_msg': msg[0:32]
    }

def parseCPX(msg):
    header = parseCPXHeader(msg)

    if(header['num_entries'] > 0):
        header['_payload'] = parseCPXItems(header, msg[20:])

    return header

def parseSimulateTouch(msg):
    return {
        'type': parseUINT32(msg[0:4]),
        'index': parseUINT32(msg[4:8]),
        'point_x': parseFloat32(msg[8:12]),
        'point_y': parseFloat32(msg[12:16])
    }

# https://github.com/opensource-apple/CF/blob/master/CFMessagePort.c
# http://forge.voodooprojects.org/svn/chameleon/trunk/i386/include/mach/message.h
def parseCFMessage(msg):
    return [
        {'ool_address': hex(parseUINT32(msg[0:4])),
         'ool_deallocate': ord(msg[4]),
         'ool_copy': ord(msg[5]),
         'ool_pad1': ord(msg[6]),
         'ool_type': ord(msg[7]),
         'ool_size': hex(parseUINT32(msg[8:12])),
         'ool_bytes': binascii.hexlify(msg[12:20])
        },
        {
         'inards_magic': hex(parseUINT32(msg[20:24])),
         'inards_msgid': hex(parseUINT32(msg[24:28])),
         'inards_convid': hex(parseUINT32(msg[28:32])),
         'inards_byteslen': hex(parseUINT32(msg[32:36]))
        },
        parseSimulateTouch(msg[36:])
    ]

def parseMsgPayload(msg):
    payload = msg['_payload']

    if(payload[0:4] == '!CPX'):
        msg['_payload'] = parseCPX(payload)

        # pp = pprint.PrettyPrinter(indent=2)
        # pp.pprint(msg)
    elif(len(payload[20:24]) == 4 and parseUINT32(payload[20:24]) == 0xf0f2f4f8):
        msg['_payload'] = parseCFMessage(payload)
    else:
        msg['_payload'] = payload

    return msg

def processData(dataItem):
    msg = parseMsgHeader(dataItem['msg'])

    return parseMsgPayload(msg)

with open(sys.argv[1], 'r') as f:
    lines = f.readlines()

    for line in lines:
        dataItem = json.loads(line)

        if('msg' in dataItem):
            dataItem['z_msg_orig'] = dataItem['msg']
            dataItem['msg'] = binascii.unhexlify(dataItem['msg'])

            msg = processData(dataItem)

            pp = pprint.PrettyPrinter(indent=2)
            pp.pprint(msg)
