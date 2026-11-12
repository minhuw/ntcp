/// An endpoint's loss and retransmission events, cumulative from its
/// creation and never reset, after Linux's SNMP counters (/proc/net/snmp
/// `Tcp`, /proc/net/netstat `TcpExt`). Each is kept on its event, as Linux
/// counts its own: a connection counts what it does, and the endpoint takes
/// the counts at the connection's next refresh, or at its reclaim
/// (`Endpoint::loss_counters`). For administrative reporting.
///
/// A segment counts once it is accepted as (possibly) submitted: direct
/// output once it is encoded, a reservation's segment at
/// `Endpoint::accept_transmit`, and each segment of a group at
/// `Endpoint::accept_transmit_group`. Output certainly not submitted counts
/// nothing.
///
/// ntcp never undoes a congestion response on evidence that its
/// retransmissions were spurious (RFC 3708, Eifel or F-RTO), so Linux's
/// TCPDSACKUndo, TCPSpuriousRTOs and their kin have no counterpart;
/// `dsack_received` reports the evidence itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LossCounters {
    /// Segments sent that carry a retransmitted copy of sequence space (a
    /// SYN or SYN-ACK, payload octets or a FIN) sent before: Linux's
    /// RetransSegs (TCP_MIB_RETRANSSEGS), which also counts each segment
    /// once, each of a TSO aggregate's segments included. A zero-window
    /// probe that repeats an octet already sent counts too, as Linux counts
    /// what it retransmits into a closed window; one that carries no new
    /// octet (an old-sequence ACK) does not. Keepalives do not count.
    pub retransmitted_segments: u64,
    /// Of `retransmitted_segments`, those sent while their connection
    /// recovered from a retransmission timeout: from the timeout until an
    /// ACK covers what was outstanding when it expired (the post-RTO
    /// repairs of RFC 6675 section 5.1, or go-back-N), as
    /// `TransportInfo::loss` reports. Linux sends these in its TCP_CA_Loss
    /// state: its TCPSlowStartRetrans, plus the timer's own resends of the
    /// head, which Linux counts in RetransSegs alone.
    pub timeout_retransmitted_segments: u64,
    /// Retransmission timer expiries that time out the flight, a SYN's or
    /// SYN-ACK's included, each backed-off expiry again: Linux's
    /// TCPTimeouts (LINUX_MIB_TCPTIMEOUTS). An expiry that finds the peer's
    /// window closed only probes it, and one that finds the head sent less
    /// than an RTO ago only rearms; neither counts, as Linux counts neither
    /// its zero-window expiry nor a timer not yet due.
    pub timeouts: u64,
    /// Tail loss probes sent (RFC 8985 section 7), of new data or
    /// retransmitting the highest segment: Linux's TCPLossProbes
    /// (LINUX_MIB_TCPLOSSPROBES). A retransmitting probe also counts in
    /// `retransmitted_segments`.
    pub loss_probes: u64,
    /// ACKs showing that a retransmitting loss probe repaired a loss: they
    /// acknowledge beyond the probe without a D-SACK for it (RFC 8985
    /// section 7.4.2): Linux's TCPLossProbeRecovery
    /// (LINUX_MIB_TCPLOSSPROBERECOVERY).
    pub loss_probe_recoveries: u64,
    /// Entries into SACK-based loss recovery (RFC 6675, or RFC 8985 RACK):
    /// Linux's TCPSackRecovery (LINUX_MIB_TCPSACKRECOVERY), which counts
    /// its entries into the Recovery state on a SACK connection.
    pub sack_recoveries: u64,
    /// Entries into fast recovery on the third duplicate ACK without SACK
    /// evidence (RFC 6582 NewReno): Linux's TCPRenoRecovery
    /// (LINUX_MIB_TCPRENORECOVERY). Linux classifies by whether the
    /// connection negotiated SACK; ntcp by whether recovery uses SACK
    /// information, so a SACK connection whose peer has sent no SACK block
    /// counts here.
    pub reno_recoveries: u64,
    /// ACKs on a connection using SACK whose first SACK block reports
    /// duplicate data (a D-SACK, RFC 2883): below the ACK, or within the
    /// second block: Linux's
    /// TCPDSACKRecv plus TCPDSACKOfoRecv (LINUX_MIB_TCPDSACKRECV,
    /// LINUX_MIB_TCPDSACKOFORECV). A D-SACK after a retransmission shows
    /// the retransmission, or its original, spurious.
    pub dsack_received: u64,
}

impl LossCounters {
    pub(crate) fn add(&mut self, other: LossCounters) {
        self.retransmitted_segments += other.retransmitted_segments;
        self.timeout_retransmitted_segments += other.timeout_retransmitted_segments;
        self.timeouts += other.timeouts;
        self.loss_probes += other.loss_probes;
        self.loss_probe_recoveries += other.loss_probe_recoveries;
        self.sack_recoveries += other.sack_recoveries;
        self.reno_recoveries += other.reno_recoveries;
        self.dsack_received += other.dsack_received;
    }
}
