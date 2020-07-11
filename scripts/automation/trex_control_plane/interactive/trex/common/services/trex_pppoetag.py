import struct
from scapy.packet import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.ppp import *
from scapy.layers.ppp import _PPP_proto
from scapy.fields import *
from scapy.modules import six

class PPPoE_Tag(Packet):
    name = "PPPoE Tag"
    fields_desc = [ ShortEnumField('tag_type', None,
                                   {0x0000: 'End-Of-List',
                                    0x0101: 'Service-Name',
                                    0x0102: 'AC-Name',
                                    0x0103: 'Host-Uniq',
                                    0x0104: 'AC-Cookie',
                                    0x0105: 'Vendor-Specific',
                                    0x0110: 'Relay-Session-Id',
                                    0x0201: 'Service-Name-Error',
                                    0x0202: 'AC-System-Error',
                                    0x0203: 'Generic-Error'}),
                    FieldLenField('tag_len', None, length_of='tag_value', fmt='H'),
                    StrLenField('tag_value', '', length_from=lambda pkt:pkt.tag_len)]

class PPPoED_Tags(Packet):
    name = "PPPoE Tag List"
    fields_desc = [PacketListField('tag_list', None, PPPoE_Tag)]


# Link Control Protocol (RFC 1661)


_PPP_lcptypes = {1: "Configure-Request",
                 2: "Configure-Ack",
                 3: "Configure-Nak",
                 4: "Configure-Reject",
                 5: "Terminate-Request",
                 6: "Terminate-Ack",
                 7: "Code-Reject",
                 8: "Protocol-Reject",
                 9: "Echo-Request",
                 10: "Echo-Reply",
                 11: "Discard-Request"}

class PPP_LCP(Packet):
    name = "PPP Link Control Protocol"
    fields_desc = [
        ByteEnumField("code", 5, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda _, val: val + 4),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]

    def mysummary(self):
        return self.sprintf('LCP %code%')

    def extract_padding(self, pay):
        return b"", pay

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            if o in [1, 2, 3, 4]:
                return PPP_LCP_Configure
            elif o in [5, 6]:
                return PPP_LCP_Terminate
            elif o == 7:
                return PPP_LCP_Code_Reject
            elif o == 8:
                return PPP_LCP_Protocol_Reject
            elif o in [9, 10]:
                return PPP_LCP_Echo
            elif o == 11:
                return PPP_LCP_Discard_Request
            else:
                return cls
        return cls


_PPP_lcp_optiontypes = {1: "Maximum-Receive-Unit",
                        2: "Async-Control-Character-Map",
                        3: "Authentication-protocol",
                        4: "Quality-protocol",
                        5: "Magic-number",
                        7: "Protocol-Field-Compression",
                        8: "Address-and-Control-Field-Compression",
                        13: "Callback"}


class PPP_LCP_Option(Packet):
    name = "PPP LCP Option"
    fields_desc = [
        ByteEnumField("type", None, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=lambda _, val: val + 2),
        StrLenField("data", None, length_from=lambda pkt: pkt.len - 2),
    ]

    def extract_padding(self, pay):
        return b"", pay

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls


class PPP_LCP_MRU_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 1, _PPP_lcp_optiontypes),
                   ByteField("len", 4),
                   ShortField("max_recv_unit", 1500)]


_PPP_LCP_auth_protocols = {
    0xc023: "Password authentication protocol",
    0xc223: "Challenge-response authentication protocol",
    0xc227: "PPP Extensible authentication protocol",
}

_PPP_LCP_CHAP_algorithms = {
    5: "MD5",
    6: "SHA1",
    128: "MS-CHAP",
    129: "MS-CHAP-v2",
}


class PPP_LCP_ACCM_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 2, _PPP_lcp_optiontypes),
        ByteField("len", 6),
        BitField("accm", 0x00000000, 32),
    ]


def adjust_auth_len(pkt, x):
    if pkt.auth_protocol == 0xc223:
        return 5
    elif pkt.auth_protocol == 0xc023:
        return 4
    else:
        return x + 4


class PPP_LCP_Auth_Protocol_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 3, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=adjust_auth_len),
        ShortEnumField("auth_protocol", 0xc023, _PPP_LCP_auth_protocols),
        ConditionalField(
            StrLenField("data", '', length_from=lambda pkt: pkt.len - 4),
            lambda pkt: pkt.auth_protocol != 0xc223
        ),
        ConditionalField(
            ByteEnumField("algorithm", 5, _PPP_LCP_CHAP_algorithms),
            lambda pkt: pkt.auth_protocol == 0xc223
        ),
    ]


_PPP_LCP_quality_protocols = {0xc025: "Link Quality Report"}


class PPP_LCP_Quality_Protocol_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 4, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=lambda _, val: val + 4),
        ShortEnumField("quality_protocol", 0xc025, _PPP_LCP_quality_protocols),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]


class PPP_LCP_Magic_Number_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 5, _PPP_lcp_optiontypes),
        ByteField("len", 6),
        IntField("magic_number", None),
    ]


_PPP_lcp_callback_operations = {
    0: "Location determined by user authentication",
    1: "Dialing string",
    2: "Location identifier",
    3: "E.164 number",
    4: "Distinguished name",
}


class PPP_LCP_Callback_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 13, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="message",
                      adjust=lambda _, val: val + 3),
        ByteEnumField("operation", 0, _PPP_lcp_callback_operations),
        StrLenField("message", "", length_from=lambda pkt: pkt.len - 3)
    ]


class PPP_LCP_Configure(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="options",
                      adjust=lambda _, val: val + 4),
        PacketListField("options", [], PPP_LCP_Option,
                        length_from=lambda pkt: pkt.len - 4),
    ]

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Configure) and self.code in [2, 3, 4] and
            other.code == 1 and other.id == self.id
        )


class PPP_LCP_Terminate(PPP_LCP):

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Terminate) and self.code == 6 and
            other.code == 5 and other.id == self.id
        )


class PPP_LCP_Code_Reject(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 7, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="rejected_packet",
                      adjust=lambda _, val: val + 4),
        PacketField("rejected_packet", None, PPP_LCP),
    ]


class PPP_LCP_Protocol_Reject(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 8, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="rejected_information",
                      adjust=lambda _, val: val + 6),
        ShortEnumField("rejected_protocol", None, _PPP_proto),
        PacketField("rejected_information", None, Packet),
    ]


class PPP_LCP_Discard_Request(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 11, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda _, val: val + 8),
        IntField("magic_number", None),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 8),
    ]


class PPP_LCP_Echo(PPP_LCP_Discard_Request):
    code = 9

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Echo) and self.code == 10 and
            other.code == 9 and self.id == other.id
        )


# Password authentication protocol (RFC 1334)


_PPP_paptypes = {1: "Authenticate-Request",
                 2: "Authenticate-Ack",
                 3: "Authenticate-Nak"}


class PPP_PAP(Packet):
    name = "PPP Password Authentication Protocol"
    fields_desc = [
        ByteEnumField("code", 1, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="data",
                      adjust=lambda _, val: val + 4),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        code = None
        if _pkt:
            code = orb(_pkt[0])
        elif "code" in kargs:
            code = kargs["code"]
            if isinstance(code, six.string_types):
                code = cls.fields_desc[0].s2i[code]

        if code == 1:
            return PPP_PAP_Request
        elif code in [2, 3]:
            return PPP_PAP_Response
        return cls

    def extract_padding(self, pay):
        return "", pay


class PPP_PAP_Request(PPP_PAP):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="username",
                      adjust=lambda pkt, val: val + 6 + len(pkt.password)),
        FieldLenField("username_len", None, fmt="B", length_of="username"),
        StrLenField("username", None,
                    length_from=lambda pkt: pkt.username_len),
        FieldLenField("passwd_len", None, fmt="B", length_of="password"),
        StrLenField("password", None, length_from=lambda pkt: pkt.passwd_len),
    ]

    def mysummary(self):
        return self.sprintf("PAP-Request username=%PPP_PAP_Request.username%"
                            " password=%PPP_PAP_Request.password%")


class PPP_PAP_Response(PPP_PAP):
    fields_desc = [
        ByteEnumField("code", 2, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="message",
                      adjust=lambda _, val: val + 5),
        FieldLenField("msg_len", None, fmt="B", length_of="message"),
        StrLenField("message", "", length_from=lambda pkt: pkt.msg_len),
    ]

    def answers(self, other):
        return isinstance(other, PPP_PAP_Request) and other.id == self.id

    def mysummary(self):
        res = "PAP-Ack" if self.code == 2 else "PAP-Nak"
        if self.msg_len > 0:
            res += self.sprintf(" msg=%PPP_PAP_Response.message%")
        return res


# Challenge Handshake Authentication protocol (RFC1994)

_PPP_chaptypes = {1: "Challenge",
                  2: "Response",
                  3: "Success",
                  4: "Failure"}


bind_layers(PPPoED, PPPoED_Tags, type=1)
bind_layers(PPP, PPP_LCP, proto=0xc021)
bind_layers(PPP, PPP_PAP, proto=0xc023)
bind_layers(Ether, PPP_IPCP, type=0x8021)