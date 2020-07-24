from scapy.layers.ppp import PPPoE, PPPoED
from scapy.layers.l2 import Ether
from .trex_pppoetag import PPPoED_Tags
from scapy.packet import NoPayload
from collections import namedtuple, OrderedDict

from ..trex_client import  PacketBuffer

from .trex_service_fast_parser import FastParser

import struct

import pprint

class PPPOEParser(FastParser):
    
    # message types
    PADI = 0x9
    PADO = 0x7
    PADR = 0x19
    PADS = 0x65
    PADT = 0xa7
    
    def __init__ (self):
        base_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/PPPoED(version=1,type=1,code="PADI",sessionid=0,len=0)/PPPoED_Tags()

        FastParser.__init__(self, base_pkt)

        self.add_field('Ethernet.dst', 'dstmac')
        self.add_field('Ethernet.src', 'srcmac')
        self.add_field('PPP over Ethernet Discovery.code', 'code')
        self.add_field('PPPoE Tag List.tag_list','tag_list', getter = self.get_tags, setter = self.set_tags)

    def get_tags (self, pkt_bytes, info):
        
        # min length
        if len(pkt_bytes) < info['offset']:
            return None
            
        options = pkt_bytes[info['offset']:]

        opt = OrderedDict()
        index = 0
        
        return opt


    def set_tags (self, pkt_bytes, info, options):

        output = bytes()

        for o, v in options.items():
            if o in self.opts:
                ot = self.opts[o]
                
                # write tag
                output += struct.pack('!B', ot['id'])
                
                # write the size and value
                if ot['type'] == 'byte':
                    output += struct.pack('!B', 1)
                    output += struct.pack('!B', v)
                    
                elif ot['type'] == 'int':
                    output += struct.pack('!B', 4)
                    output += struct.pack('!I', v)
                    
                elif ot['type'] == 'str':
                    output += struct.pack('!B', len(v))
                    output += struct.pack('!{0}s'.format(len(v)), v)
                    
                
                
        # write end
        output += struct.pack('!B', 255)
        
        return pkt_bytes[:info['offset']] + output + pkt_bytes[info['offset'] + len(output):]
        
    def disc (self, mac):
        '''
            generates a DHCP discovery packet
        '''
        
        # generate a new packet
        obj = self.clone()
        obj.srcmac = mac
        
        return PacketBuffer(obj.raw())
        

    def req (self, srcmac, dstmac):
        '''
            generate a new request packet
        '''
        
        # generate a new packet
        obj = self.clone()
        obj.srcmac = srcmac
        obj.dstmac = dstmac
        obj.code = self.PADR
                
        return PacketBuffer(obj.raw())
        
        

    def release (self, xid, client_mac, client_ip, server_mac, server_ip):
        '''
            generate a release request packet
        '''
        
        # generate a new packet
        obj = self.clone()
        
        obj.dstmac = server_mac
        obj.srcmac = client_mac
        
        obj.dstip  = server_ip
        obj.srcip  = client_ip
        
        obj.fix_chksum()
        
        obj.ciaddr = client_ip
        obj.chaddr = client_mac
        obj.xid    = xid
        
        obj.options = {'message-type': 7, 'server_id': server_ip}
        
        return PacketBuffer(obj.raw())
 

