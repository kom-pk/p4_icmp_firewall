/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_ICMP = 1;

const bit<32> STATE_SIZE = 1024;  // Fixed: bit<32> for register size (and value fits)
const bit<32> COUNTER_SIZE = 1024;  // Fixed: same
const bit<32> RATE_THRESHOLD = 10;  // 

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8>  type;        // 8=request, 0=reply
    bit<8>  code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence;
}

struct metadata {
    bit<1>  direction;      // 0=outbound, 1=inbound
    bit<32> flow_hash;      // For state tracking (index)
    bit<32> src_hash;       // For rate limiting (index)
    bit<16> stored_id;
    bit<16> stored_seq;
    bit<32> icmp_count;
    bit<1>  allowed_inbound;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(STATE_SIZE) icmp_state;     // Packed ID (high 16) + seq (low 16)
    register<bit<32>>(COUNTER_SIZE) icmp_counter; // Per-src inbound count

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_direction(bit<1> dir) {
        meta.direction = dir;
    }

    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        default_action = NoAction();
    }
    
    action set_allowed() {
        meta.allowed_inbound = 1;
    }
    
    table allow_inbound_src {
        key = {
            hdr.ipv4.srcAddr: exact;  // Match external src IP
        }
        actions = {
            set_allowed;
            NoAction;
        }
        size = 1024;  // Enough for many IPs
        default_action = NoAction();  // No match = not allowed
    }

    // Fixed: Compute hash without modifying packet headers
    action compute_flow_hash(ip4Addr_t src, ip4Addr_t dst) {
        hash(meta.flow_hash, HashAlgorithm.crc16, (bit<32>)0,
             {src, dst, hdr.ipv4.protocol, hdr.icmp.identifier, hdr.icmp.sequence},
             STATE_SIZE);  // Use bit<32> constant
    }

    action compute_src_hash() {
        hash(meta.src_hash, HashAlgorithm.crc32, (bit<32>)0,
             {hdr.ipv4.srcAddr},
             COUNTER_SIZE);  // Same
    }

    action increment_counter() {
        icmp_counter.read(meta.icmp_count, meta.src_hash);
        meta.icmp_count = meta.icmp_count + 1;
        icmp_counter.write(meta.src_hash, meta.icmp_count);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            check_ports.apply();  // Sets direction
            
			if (!hdr.icmp.isValid()) {  // not ICMP packet get dropped
				drop();
			}
			
            if (hdr.icmp.isValid()) {
                compute_src_hash();  // Prep for counter

                if (meta.direction == 0 && hdr.icmp.type == 8) {  // Outbound request: Set state
                    // Use original src/dst for outbound hash
                    compute_flow_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
                    bit<32> packed = ((bit<32>)hdr.icmp.identifier << 16) | (bit<32>)hdr.icmp.sequence;
                    icmp_state.write(meta.flow_hash, packed);
                    // Reset counter for internal src if needed (optional)
                    icmp_counter.write(meta.src_hash, 0);
                } else if (meta.direction == 1) {  // Inbound
					
					allow_inbound_src.apply(); // whitelist freeway
					if (meta.allowed_inbound == 1) {
						return;
					}
					
                    // Rate limit first (applies to all inbound ICMP)
                    increment_counter();
                    if (meta.icmp_count > RATE_THRESHOLD) {
                        drop();
                        return;  // Early exit
                    }

                    if (hdr.icmp.type == 0) {  // Reply: Validate state
                        // Use swapped src/dst for symmetric hash (no header mod)
                        compute_flow_hash(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr);  // Swap in call
                        bit<32> stored_packed;
                        icmp_state.read(stored_packed, meta.flow_hash);
                        meta.stored_id = (bit<16>)(stored_packed >> 16);
                        meta.stored_seq = (bit<16>)(stored_packed & 0xFFFF);  // Safer unpack
                        if (hdr.icmp.identifier != meta.stored_id || hdr.icmp.sequence != meta.stored_seq) {
                            drop();
                        }
                    } else {
						
						if (meta.allowed_inbound == 0) {
							drop(); // Block inbound requests or other types
						} 
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
