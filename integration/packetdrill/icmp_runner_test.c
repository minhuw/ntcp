// SPDX-License-Identifier: GPL-2.0-or-later
/* Unit-only access to the real mapping/send paths; no socket or timed run. */
#include "run_packet.c"
#include "so_testing.c"
#include "icmp_packet.h"
#include "parse.h"

static int callback_errno;
static int callback_status;
static int callback_send(void *unused, const void *bytes, size_t length)
{
	assert(bytes && length);
	errno = callback_errno;
	return callback_status;
}

static void dump(const char *name, struct packet *packet)
{
	printf("%s ", name);
	for (u32 i = 0; i < packet->ip_bytes; ++i)
		printf("%02x", packet_start(packet)[i]);
	puts("");
}

static struct packet *mapped(struct state *state, struct socket *socket,
                             struct packet *script, int total, u32 seq,
                             const char *name)
{
	char *error = NULL;
	struct packet *packet = packet_copy(script);
	assert(map_inbound_packet(state, socket, packet, &error) == STATUS_OK);
	assert(error == NULL);
	assert(send_live_ip_packet(state, packet, &error) == STATUS_OK);
	assert(error == NULL);
	assert(packet->ip_bytes == 56); /* exactly 20 + 8 + 28, not total_len */
	struct ipv4 *quote = packet_echoed_ipv4_header(packet);
	assert(ntohs(quote->tot_len) == total);
	assert(ntohl(*packet_echoed_tcp_seq(packet)) == seq);
	assert(ipv4_checksum(quote, 20) == 0);
	assert(ipv4_checksum(packet->ipv4, 20) == 0);
	assert(ipv4_checksum(packet->icmpv4, 36) == 0);
	dump(name, packet);
	return packet;
}

int main(void)
{
	struct config config;
	set_default_config(&config);
	config.script_path = "icmp-unit";
	struct script script = {0};
	copy_script(
		"0 > S 0:1000(1000) <mss 1460,nop,nop,sackOK,nop,wscale 8,FO abcd1234,nop,nop>\n"
		"0 < icmp unreachable frag_needed mtu 800\n"
		"0 < icmp unreachable frag_needed mtu 840 [0:1000(1000)]\n"
		"0 < icmp unreachable frag_needed mtu 840 [9:1009(1000)]\n"
		"0 < icmp unreachable frag_needed mtu 840 [0:0(0)]\n"
		"0 < icmp unreachable frag_needed mtu 840 [0:999(999)]\n",
		&script);
	char *argv[] = {"icmp-unit", NULL};
	struct invocation invocation = {1, argv, &config, &script};
	assert(parse_script(&config, &script, &invocation) == STATUS_OK);
	struct packet *out = script.event_list->event.packet;
	struct event *e = script.event_list->next;
	struct packet *omitted = e->event.packet;
	struct packet *explicit = (e = e->next)->event.packet;
	struct packet *override = (e = e->next)->event.packet;
	struct packet *zero = (e = e->next)->event.packet;
	struct packet *different = (e = e->next)->event.packet;
	assert(omitted->flags & FLAG_ICMP_ECHO_UNSPECIFIED);
	assert(!(explicit->flags & FLAG_ICMP_ECHO_UNSPECIFIED));
	assert(!(zero->flags & FLAG_ICMP_ECHO_UNSPECIFIED));
	assert(out->tcp->doff == 10 && out->ip_bytes == 1060);

	struct socket socket = {0};
	socket.live.local_isn = 0x12345670;
	struct in_addr local, remote;
	assert(inet_pton(AF_INET, "192.168.0.1", &local) == 1);
	assert(inet_pton(AF_INET, "192.0.2.1", &remote) == 1);
	ip_from_ipv4(&local, &socket.live.local.ip);
	ip_from_ipv4(&remote, &socket.live.remote.ip);
	socket.live.local.port = htons(40001);
	socket.live.remote.port = htons(8080);
	struct tuple tuple;
	socket_get_outbound(&socket.live, &tuple);
	set_packet_tuple(out, &tuple);
	out->tcp->seq = htonl(socket.live.local_isn);
	out->ipv4->id = htons(5432);
	out->ipv4->ttl = 64;
	checksum_packet(out);
	socket.last_outbound_tcp_header = *out->tcp;
	remember_outbound_ip_header(&socket, out);
	assert(socket.last_outbound_ipv4_valid);
	/* Capture is independent of later sequence mapping/buffer lifetime. */
	out->tcp->seq = 0;

	struct packetdrill_interface ifc = {.netdev_send = callback_send};
	struct so_netdev netdev = {.netdev = {.ops = &so_netdev_ops}, .ifc = &ifc};
	struct state state = {.config = &config, .netdev = &netdev.netdev};
	struct packet *p = mapped(&state, &socket, omitted, 1060, 0x12345670, "omitted");
	assert(!memcmp(packet_echoed_ipv4_header(p), out->ipv4, 20));
	packet_free(p);
	packet_free(mapped(&state, &socket, explicit, 1060, 0x12345670, "explicit"));
	packet_free(mapped(&state, &socket, override, 1040, 0x12345679, "override"));
	/* An explicit nonzero sequence can select the actual captured packet. */
	out->tcp->seq = htonl(0x12345679);
	socket.last_outbound_tcp_header = *out->tcp;
	remember_outbound_ip_header(&socket, out);
	packet_free(mapped(&state, &socket, override, 1060, 0x12345679, "override_match"));
	socket.last_outbound_tcp_header.seq = htonl(0x12345670);
	packet_free(mapped(&state, &socket, zero, 40, 0x12345670, "zero"));
	packet_free(mapped(&state, &socket, different, 1039, 0x12345670, "different"));

	/* No tuple or sequence substitution on a last-template miss. */
	socket.last_outbound_tcp_header.src_port ^= htons(1);
	packet_free(mapped(&state, &socket, explicit, 1040, 0x12345670, "port_miss"));
	socket.last_outbound_tcp_header.src_port ^= htons(1);
	socket.last_outbound_ipv4_header.src_ip.s_addr ^= htonl(1);
	packet_free(mapped(&state, &socket, explicit, 1040, 0x12345670, "ip_miss"));
	socket.last_outbound_ipv4_header.src_ip.s_addr ^= htonl(1);
	socket.last_outbound_tcp_header.seq = htonl(0x12345671);
	packet_free(mapped(&state, &socket, omitted, 40, 0x12345670, "sequence_miss"));
	socket.last_outbound_tcp_header.seq = htonl(0x12345670);
	socket.last_outbound_ipv4_valid = false;
	packet_free(mapped(&state, &socket, explicit, 1040, 0x12345670, "no_template"));
	socket.last_outbound_ipv4_valid = true;

	/* Explicit post-construction malformed header edits must survive. */
	char *error = NULL;
	for (int corruption = 0; corruption < 3; ++corruption) {
		p = packet_copy(explicit);
		struct ipv4 *quote = packet_echoed_ipv4_header(p);
		if (corruption == 1)
			quote->tot_len = htons(17);
		else
			quote->check = corruption == 2 ? 0 : htons(0xbeef);
		u16 saved_check = quote->check;
		assert(!generated_icmpv4_quote(p));
		assert(map_inbound_packet(&state, &socket, p, &error) == STATUS_OK);
		assert(send_live_ip_packet(&state, p, &error) == STATUS_OK);
		assert(ntohs(quote->tot_len) == (corruption == 1 ? 17 : 1040));
		assert(quote->check == saved_check);
		assert(ipv4_checksum(p->icmpv4, 36) == 0);
		dump(corruption == 1 ? "bad_length" :
		     corruption == 2 ? "zero_checksum" : "bad_checksum", p);
		packet_free(p);
	}

	struct ip_info info = {{TOS_CHECK_NONE, 0}, 0};
	p = new_icmp_packet(AF_INET, DIRECTION_INBOUND, "unreachable", "port_unreachable",
	                    IPPROTO_UDP, 0, 100, info, -1, 0, &error);
	assert(p && !error);
	assert(map_inbound_packet(&state, &socket, p, &error) == STATUS_OK);
	assert(send_live_ip_packet(&state, p, &error) == STATUS_OK);
	assert(ntohs(packet_echoed_ipv4_header(p)->tot_len) == 128);
	assert(ipv4_checksum(packet_echoed_ipv4_header(p), 20) == 0);
	assert(ipv4_checksum(p->icmpv4, 36) == 0);
	packet_free(p);

	/* An IPv4-options packet cannot be captured as a fixed 20-byte header. */
	out->ipv4->ihl = 6;
	remember_outbound_ip_header(&socket, out);
	assert(!socket.last_outbound_ipv4_valid);
	out->ipv4->ihl = 5;

	p = new_icmp_packet(AF_INET, DIRECTION_INBOUND, "unreachable", "frag_needed",
	                    IPPROTO_RAW, 0, 36, info, 840, 0, &error);
	/* Raw embedded bytes (including a zero/bad checksum) are never inferred. */
	memcpy(p->icmpv4 + 1, packet_echoed_ipv4_header(explicit), 28);
	((struct ipv4 *)(p->icmpv4 + 1))->check = 0;
	assert(!generated_icmpv4_quote(p));
	u8 raw[28];
	memcpy(raw, p->icmpv4 + 1, sizeof(raw));
	assert(map_inbound_packet(&state, &socket, p, &error) == STATUS_OK);
	assert(send_live_ip_packet(&state, p, &error) == STATUS_OK);
	assert(!memcmp(raw, p->icmpv4 + 1, sizeof(raw)));
	dump("raw", p);
	packet_free(p);

	/* The unchanged IPv6 quote path still maps sequence/tuple and computes
	 * the enclosing ICMPv6 pseudoheader checksum. No socket support claim. */
	struct in6_addr local6, remote6;
	assert(inet_pton(AF_INET6, "2001:db8::1", &local6) == 1);
	assert(inet_pton(AF_INET6, "2001:db8::2", &remote6) == 1);
	ip_from_ipv6(&local6, &socket.live.local.ip);
	ip_from_ipv6(&remote6, &socket.live.remote.ip);
	p = new_icmp_packet(AF_INET6, DIRECTION_INBOUND, "packet_too_big", NULL,
	                    IPPROTO_TCP, 9, 1000, info, 1280, 0, &error);
	assert(p && !error);
	assert(!generated_icmpv4_quote(p));
	assert(map_inbound_packet(&state, &socket, p, &error) == STATUS_OK);
	assert(send_live_ip_packet(&state, p, &error) == STATUS_OK);
	assert(p->ip_bytes == 96);
	assert(ntohl(*packet_echoed_tcp_seq(p)) == 0x12345679);
	assert(ntohs(packet_echoed_ipv6_header(p)->payload_len) == 1020);
	assert(tcp_udp_v6_checksum(&p->ipv6->src_ip, &p->ipv6->dst_ip,
	                          IPPROTO_ICMPV6, p->icmpv6, 56) == 0);
	dump("ipv6", p);
	remember_outbound_ip_header(&socket, p);
	assert(!socket.last_outbound_ipv4_valid);

	/* Exercise the actual shared-object callback adapter and send error. */
	callback_status = -1;
	callback_errno = EINVAL;
	assert(send_live_ip_packet(&state, p, &error) == -1);
	assert(errno == EINVAL);
	assert(strstr(error, "netdev_send failed") && strstr(error, "errno 22"));
	assert(strstr(error, strerror(EINVAL)));
	printf("error %s\n", error);
	free(error);
	error = NULL;
	callback_errno = 0;
	errno = EBUSY;
	assert(send_live_ip_packet(&state, p, &error) == -1);
	assert(strstr(error, "callback did not set errno"));
	free(error);
	packet_free(p);
	return 0;
}
