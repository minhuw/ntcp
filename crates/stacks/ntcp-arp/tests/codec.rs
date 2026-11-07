use core::net::Ipv4Addr;
use ntcp_arp::*;

const HOST: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const ROUTER: [u8; 6] = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];

// A request in the form Linux broadcasts to resolve 192.168.1.1 from
// 192.168.1.10 (ar$tha zero), before minimum-frame padding: the Ethernet
// header, then hrd, pro, hln, pln, op, sha, spa, tha and tpa.
const LINUX_REQUEST: [u8; 42] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0xc0, 0xa8, 0x01, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
];
// The reply in the form Linux sends it from 192.168.1.1, unicast to the
// requester's MAC.
const LINUX_REPLY: [u8; 42] = [
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x52, 0x54, 0x00, 0xab, 0xcd, 0xef, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x52, 0x54, 0x00, 0xab, 0xcd, 0xef, 0xc0, 0xa8, 0x01, 0x01,
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0xc0, 0xa8, 0x01, 0x0a,
];

fn request() -> Arp {
    Arp {
        operation: Operation::Request,
        sender_mac: HOST,
        sender_ip: Ipv4Addr::new(192, 168, 1, 10),
        target_mac: [0; 6],
        target_ip: Ipv4Addr::new(192, 168, 1, 1),
    }
}
fn reply() -> Arp {
    Arp {
        operation: Operation::Reply,
        sender_mac: ROUTER,
        sender_ip: Ipv4Addr::new(192, 168, 1, 1),
        target_mac: HOST,
        target_ip: Ipv4Addr::new(192, 168, 1, 10),
    }
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# Ethernet packet data:
//# 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
//# Packet Radio Net.)
//# 16.bit: (ar$pro) Protocol address space.  For Ethernet
//# hardware, this is from the set of type
//# fields ether_typ$<protocol>.
//# 8.bit: (ar$hln) byte length of each hardware address
//# 8.bit: (ar$pln) byte length of each protocol address
//# 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
//# nbytes: (ar$sha) Hardware address of sender of this
//# packet, n from the ar$hln field.
//# mbytes: (ar$spa) Protocol address of sender of this
//# packet, m from the ar$pln field.
//# nbytes: (ar$tha) Hardware address of target of this
//# packet (if known).
//# mbytes: (ar$tpa) Protocol address of target.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# ares_op$REQUEST (= 1, high byte transmitted first) and
//# ares_op$REPLY   (= 2),
//# and
//# ares_hrd$Ethernet (= 1).
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# There are no padding bytes between addresses.  The packet data
//# should be viewed as a byte stream in which only 3 byte pairs are
//# defined to be words (ar$hrd, ar$pro and ar$op) which are sent
//# most significant byte first (Ethernet/PDP-10 byte style).
#[test]
fn rfc826_field_layout_round_trips() {
    // Each field at its RFC 826 offset: hrd 0, pro 2, hln 4, pln 5, op 6,
    // sha 8, spa 14 (8 + hln), tha 18, tpa 24 (18 + hln); words big-endian.
    let arp = Arp {
        operation: Operation::Reply,
        sender_mac: [1, 2, 3, 4, 5, 6],
        sender_ip: Ipv4Addr::new(7, 8, 9, 10),
        target_mac: [11, 12, 13, 14, 15, 16],
        target_ip: Ipv4Addr::new(17, 18, 19, 20),
    };
    let mut out = [0xee; 32];
    assert_eq!(encode(&mut out, &arp), Ok(ARP_LEN));
    assert_eq!(
        out[..28],
        [
            0, 1, 8, 0, 6, 4, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20
        ]
    );
    assert_eq!(out[28..], [0xee; 4], "exactly 28 octets are written");
    assert_eq!(parse(&out[..28]), Ok(arp));
    assert_eq!(Operation::Request.code(), 1);
    assert_eq!(Operation::Reply.code(), 2);
    assert_eq!(encode(&mut out[..27], &arp), Err(Error::Truncated));
}

#[test]
fn linux_request_and_reply_vectors() {
    for (frame, arp, destination, source) in [
        (LINUX_REQUEST, request(), [0xff; 6], HOST),
        (LINUX_REPLY, reply(), HOST, ROUTER),
    ] {
        assert_eq!(parse(&frame[14..]), Ok(arp));
        let mut body = [0; ARP_LEN];
        encode(&mut body, &arp).unwrap();
        assert_eq!(body, frame[14..]);
        // The full frame, padded with zeros to the 60-octet minimum.
        let mut out = [0x5a; 64];
        assert_eq!(encode_frame(&mut out, source, destination, &arp), Ok(60));
        assert_eq!(out[..42], frame);
        assert_eq!(out[42..60], [0; 18]);
        assert_eq!(parse_frame(&out[..60]), Ok((destination, source, arp)));
        assert_eq!(parse_frame(&frame), Ok((destination, source, arp)));
        assert_eq!(
            encode_frame(&mut out[..59], source, destination, &arp),
            Err(Error::Truncated)
        );
    }
}

#[test]
fn trailing_padding_is_ignored() {
    let mut padded = [0xa5; 46];
    padded[..28].copy_from_slice(&LINUX_REQUEST[14..]);
    assert_eq!(parse(&padded), Ok(request()));
    assert_eq!(parse(&LINUX_REQUEST[14..41]), Err(Error::Truncated));
    assert_eq!(parse(&[]), Err(Error::Truncated));
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# ?Do I have the hardware type in ar$hrd?
//# Yes: (almost definitely)
//# [optionally check the hardware length ar$hln]
//# ?Do I speak the protocol in ar$pro?
//# Yes:
//# [optionally check the protocol length ar$pln]
#[test]
fn every_rejection_is_distinct() {
    let body: [u8; 28] = LINUX_REPLY[14..].try_into().unwrap();
    let cases: [(usize, &[u8], Error); 9] = [
        (0, &[0, 6], Error::HardwareType), // IEEE 802
        (0, &[0, 0], Error::HardwareType),
        (2, &[0x86, 0xdd], Error::ProtocolType), // IPv6
        (4, &[8], Error::HardwareLength),
        (4, &[0], Error::HardwareLength),
        (5, &[16], Error::ProtocolLength),
        (6, &[0, 0], Error::Operation),
        (6, &[0, 3], Error::Operation), // RARP request
        (6, &[1, 1], Error::Operation),
    ];
    for (at, bytes, error) in cases {
        let mut bad = body;
        bad[at..at + bytes.len()].copy_from_slice(bytes);
        assert_eq!(parse(&bad), Err(error), "{at} {bytes:?}");
    }
    let mut frame = LINUX_REPLY;
    frame[12..14].copy_from_slice(&[0x81, 0x00]);
    assert_eq!(parse_frame(&frame), Err(Error::EtherType));
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    assert_eq!(parse_frame(&frame), Err(Error::EtherType));
    assert_eq!(parse_frame(&frame[..10]), Err(Error::Truncated));
}
