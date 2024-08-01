#include "speed_counters.hpp"

#include "fast_library.hpp"

#include "iana_ip_protocols.hpp"

extern time_t current_inaccurate_time;
extern log4cpp::Category& logger;

// This function increments all our accumulators according to data from packet
void increment_incoming_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    current_element.total.in_packets += sampled_number_of_packets;
    current_element.total.in_bytes += sampled_number_of_bytes;

    // Count fragmented IP packets
    if (current_packet.ip_fragmented) {
        current_element.fragmented.in_packets += sampled_number_of_packets;
        current_element.fragmented.in_bytes += sampled_number_of_bytes;
    }

    // Count dropped packets
    if (current_packet.forwarding_status == forwarding_status_t::dropped) {
        current_element.dropped.in_packets += sampled_number_of_packets;
        current_element.dropped.in_bytes += sampled_number_of_bytes;
    }

    // Count per protocol packets
    if (current_packet.protocol == IPPROTO_TCP) {
        current_element.tcp.in_packets += sampled_number_of_packets;
        current_element.tcp.in_bytes += sampled_number_of_bytes;

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            current_element.tcp_syn.in_packets += sampled_number_of_packets;
            current_element.tcp_syn.in_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.protocol == IPPROTO_UDP) {
        current_element.udp.in_packets += sampled_number_of_packets;
        current_element.udp.in_bytes += sampled_number_of_bytes;

    } else {
        // TBD
    }

    // ICMP uses different protocol numbers for IPv4 and IPv6 and we need handle it
    if (current_packet.ip_protocol_version == 4) {
        if (current_packet.protocol == IpProtocolNumberICMP) {
            current_element.icmp.in_packets += sampled_number_of_packets;
            current_element.icmp.in_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.ip_protocol_version == 6) {

        if (current_packet.protocol == IpProtocolNumberIPV6_ICMP) {
            current_element.icmp.in_packets += sampled_number_of_packets;
            current_element.icmp.in_bytes += sampled_number_of_bytes;
        }

    }

    // rafael decoders
    if (current_packet.protocol == IPPROTO_UDP || current_packet.protocol == IPPROTO_TCP) {
        // decoder port0
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_port0.in_packets += sampled_number_of_packets;
            current_element.decoder_port0.in_bytes += sampled_number_of_bytes;
        }
        // decoder dns
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            current_element.decoder_dns.in_packets += sampled_number_of_packets;
            current_element.decoder_dns.in_bytes += sampled_number_of_bytes;
        }
        // decoder ntp
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_ntp.in_packets += sampled_number_of_packets;
            current_element.decoder_ntp.in_bytes += sampled_number_of_bytes;
        }
        // decoder ssdp
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_ssdp.in_packets += sampled_number_of_packets;
            current_element.decoder_ssdp.in_bytes += sampled_number_of_bytes;
        }
        // decoder ldap
        if(current_packet.source_port == 389 || current_packet.destination_port == 389 ||
             current_packet.source_port == 636 || current_packet.destination_port == 636 )
        {
            current_element.decoder_ldap.in_packets += sampled_number_of_packets;
            current_element.decoder_ldap.in_bytes += sampled_number_of_bytes;
        }
        // decoder chargen
        if(current_packet.source_port == 19 || current_packet.destination_port == 19)
        {
            current_element.decoder_chargen.in_packets += sampled_number_of_packets;
            current_element.decoder_chargen.in_bytes += sampled_number_of_bytes;
        }

        // decoder http
        if(current_packet.source_port == 80 || current_packet.destination_port == 80)
        {
            current_element.decoder_http.in_packets += sampled_number_of_packets;
            current_element.decoder_http.in_bytes += sampled_number_of_bytes;
        }
    }

    // udp only decoders
    if (current_packet.protocol == IPPROTO_UDP) {
        // decoder udphighports
        if(current_packet.source_port > 1024 && current_packet.destination_port > 1024)
        {
            current_element.decoder_udphighports.in_packets += sampled_number_of_packets;
            current_element.decoder_udphighports.in_bytes += sampled_number_of_bytes;
        }
        // decoder quic
        if(current_packet.source_port == 443 || current_packet.destination_port == 443)
        {
            current_element.decoder_quic.in_packets += sampled_number_of_packets;
            current_element.decoder_quic.in_bytes += sampled_number_of_bytes;
        }
    }

    // tcp only decoders
    if (current_packet.protocol == IPPROTO_TCP) {
        // decoder tcphighports
        if(current_packet.source_port > 1024 && current_packet.destination_port > 1024)
        {
            current_element.decoder_tcphighports.in_packets += sampled_number_of_packets;
            current_element.decoder_tcphighports.in_bytes += sampled_number_of_bytes;
        }
        // decoder https
        if(current_packet.source_port == 443 || current_packet.destination_port == 443)
        {
            current_element.decoder_https.in_packets += sampled_number_of_packets;
            current_element.decoder_https.in_bytes += sampled_number_of_bytes;
        }
    }

}

// Increment fields using data from specified packet
void increment_outgoing_counters(subnet_counter_t& current_element,
                                 const simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element.last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    current_element.total.out_packets += sampled_number_of_packets;
    current_element.total.out_bytes += sampled_number_of_bytes;

    // Fragmented IP packets
    if (current_packet.ip_fragmented) {
        current_element.fragmented.out_packets += sampled_number_of_packets;
        current_element.fragmented.out_bytes += sampled_number_of_bytes;
    }

    // Count dropped packets
    if (current_packet.forwarding_status == forwarding_status_t::dropped) {
        current_element.dropped.out_packets += sampled_number_of_packets;
        current_element.dropped.out_bytes += sampled_number_of_bytes;
    }

    if (current_packet.protocol == IPPROTO_TCP) {
        current_element.tcp.out_packets += sampled_number_of_packets;
        current_element.tcp.out_bytes += sampled_number_of_bytes;

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            current_element.tcp_syn.out_packets += sampled_number_of_packets;
            current_element.tcp_syn.out_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.protocol == IPPROTO_UDP) {
        current_element.udp.out_packets += sampled_number_of_packets;
        current_element.udp.out_bytes += sampled_number_of_bytes;

    } else {
    }

    // ICMP uses different protocol numbers for IPv4 and IPv6 and we need handle it
    if (current_packet.ip_protocol_version == 4) {
        if (current_packet.protocol == IpProtocolNumberICMP) {
            current_element.icmp.out_packets += sampled_number_of_packets;
            current_element.icmp.out_bytes += sampled_number_of_bytes;
        }

    } else if (current_packet.ip_protocol_version == 6) {

        if (current_packet.protocol == IpProtocolNumberIPV6_ICMP) {
            current_element.icmp.out_packets += sampled_number_of_packets;
            current_element.icmp.out_bytes += sampled_number_of_bytes;
        }

    }

    // rafael decoders
    if (current_packet.protocol == IPPROTO_UDP || current_packet.protocol == IPPROTO_TCP) {
        // decoder port0
        if(current_packet.source_port == 0 || current_packet.destination_port == 0)
        {
            current_element.decoder_port0.out_packets += sampled_number_of_packets;
            current_element.decoder_port0.out_bytes += sampled_number_of_bytes;
        }
        // decoder dns
        if(current_packet.source_port == 53 || current_packet.destination_port == 53)
        {
            current_element.decoder_dns.out_packets += sampled_number_of_packets;
            current_element.decoder_dns.out_bytes += sampled_number_of_bytes;
        }
        // decoder ntp
        if(current_packet.source_port == 123 || current_packet.destination_port == 123)
        {
            current_element.decoder_ntp.out_packets += sampled_number_of_packets;
            current_element.decoder_ntp.out_bytes += sampled_number_of_bytes;
        }
        // decoder ssdp
        if(current_packet.source_port == 1900 || current_packet.destination_port == 1900)
        {
            current_element.decoder_ssdp.out_packets += sampled_number_of_packets;
            current_element.decoder_ssdp.out_bytes += sampled_number_of_bytes;
        }
        // decoder ldap
        if(current_packet.source_port == 389 || current_packet.destination_port == 389 ||
             current_packet.source_port == 636 || current_packet.destination_port == 636 )
        {
            current_element.decoder_ldap.out_packets += sampled_number_of_packets;
            current_element.decoder_ldap.out_bytes += sampled_number_of_bytes;
        }
        // decoder chargen
        if(current_packet.source_port == 19 || current_packet.destination_port == 19)
        {
            current_element.decoder_chargen.out_packets += sampled_number_of_packets;
            current_element.decoder_chargen.out_bytes += sampled_number_of_bytes;
        }
        // decoder http
        if(current_packet.source_port == 80 || current_packet.destination_port == 80)
        {
            current_element.decoder_http.out_packets += sampled_number_of_packets;
            current_element.decoder_http.out_bytes += sampled_number_of_bytes;
        }
    }

    // udp only decoders
    if (current_packet.protocol == IPPROTO_UDP) {
        // decoder udphighports
        if(current_packet.source_port > 1024 && current_packet.destination_port > 1024)
        {
            current_element.decoder_udphighports.out_packets += sampled_number_of_packets;
            current_element.decoder_udphighports.out_bytes += sampled_number_of_bytes;
        }
        // decoder quic
        if(current_packet.source_port == 443 || current_packet.destination_port == 443)
        {
            current_element.decoder_quic.out_packets += sampled_number_of_packets;
            current_element.decoder_quic.out_bytes += sampled_number_of_bytes;
        }
    }

    // tcp only decoders
    if (current_packet.protocol == IPPROTO_TCP) {
        // decoder tcphighports
        if(current_packet.source_port > 1024 && current_packet.destination_port > 1024)
        {
            current_element.decoder_tcphighports.out_packets += sampled_number_of_packets;
            current_element.decoder_tcphighports.out_bytes += sampled_number_of_bytes;
        }
        // decoder https
        if(current_packet.source_port == 443 || current_packet.destination_port == 443)
        {
            current_element.decoder_https.out_packets += sampled_number_of_packets;
            current_element.decoder_https.out_bytes += sampled_number_of_bytes;
        }
    }


}


// These build_* functions are called from our heavy computation path in recalculate_speed()
// and you may have an idea that making them inline will help
// We did this experiment and inlining clearly did speed calculation performance 1-2% worse

// We calculate speed from packet counters here
void build_speed_counters_from_packet_counters(subnet_counter_t& new_speed_element, const subnet_counter_t& data_counters, double speed_calc_period) {
    new_speed_element.total.calculate_speed(data_counters.total, speed_calc_period);
    new_speed_element.dropped.calculate_speed(data_counters.dropped, speed_calc_period);

    new_speed_element.fragmented.calculate_speed(data_counters.fragmented, speed_calc_period);
    new_speed_element.tcp_syn.calculate_speed(data_counters.tcp_syn, speed_calc_period);

    // rafael decoders
    // decoder port0
    new_speed_element.decoder_port0.calculate_speed(data_counters.decoder_port0, speed_calc_period);
    // decoder dns
    new_speed_element.decoder_dns.calculate_speed(data_counters.decoder_dns, speed_calc_period);
    // decoder ntp
    new_speed_element.decoder_ntp.calculate_speed(data_counters.decoder_ntp, speed_calc_period);
    // decoder ssdp
    new_speed_element.decoder_ssdp.calculate_speed(data_counters.decoder_ssdp, speed_calc_period);
    // decoder ldap
    new_speed_element.decoder_ldap.calculate_speed(data_counters.decoder_ldap, speed_calc_period);
    // decoder chargen
    new_speed_element.decoder_chargen.calculate_speed(data_counters.decoder_chargen, speed_calc_period);
    // decoder tcphighports
    new_speed_element.decoder_tcphighports.calculate_speed(data_counters.decoder_tcphighports, speed_calc_period);
    // decoder udphighports
    new_speed_element.decoder_udphighports.calculate_speed(data_counters.decoder_udphighports, speed_calc_period);
    // decoder http
    new_speed_element.decoder_http.calculate_speed(data_counters.decoder_http, speed_calc_period);
    // decoder https
    new_speed_element.decoder_https.calculate_speed(data_counters.decoder_https, speed_calc_period);
    // decoder quic
    new_speed_element.decoder_quic.calculate_speed(data_counters.decoder_quic, speed_calc_period);

    new_speed_element.tcp.calculate_speed(data_counters.tcp, speed_calc_period);
    new_speed_element.udp.calculate_speed(data_counters.udp, speed_calc_period);
    new_speed_element.icmp.calculate_speed(data_counters.icmp, speed_calc_period);
}

// We use this code to create smoothed speed of traffic from instant speed (per second)
void build_average_speed_counters_from_speed_counters(subnet_counter_t& current_average_speed_element,
                                                      const subnet_counter_t& new_speed_element,
                                                      double exp_value) {

    current_average_speed_element.total.calulate_exponential_moving_average_speed(new_speed_element.total, exp_value);
    current_average_speed_element.dropped.calulate_exponential_moving_average_speed(new_speed_element.dropped, exp_value);

    current_average_speed_element.fragmented.calulate_exponential_moving_average_speed(new_speed_element.fragmented, exp_value);
    current_average_speed_element.tcp_syn.calulate_exponential_moving_average_speed(new_speed_element.tcp_syn, exp_value);
    
    // rafael decoders
    // decoder port0
    current_average_speed_element.decoder_port0.calulate_exponential_moving_average_speed(new_speed_element.decoder_port0, exp_value);
    // decoder dns
    current_average_speed_element.decoder_dns.calulate_exponential_moving_average_speed(new_speed_element.decoder_dns, exp_value);
    // decoder ntp
    current_average_speed_element.decoder_ntp.calulate_exponential_moving_average_speed(new_speed_element.decoder_ntp, exp_value);
    // decoder ssdp
    current_average_speed_element.decoder_ssdp.calulate_exponential_moving_average_speed(new_speed_element.decoder_ssdp, exp_value);
    // decoder ldap
    current_average_speed_element.decoder_ldap.calulate_exponential_moving_average_speed(new_speed_element.decoder_ldap, exp_value);
    // decoder chargen
    current_average_speed_element.decoder_chargen.calulate_exponential_moving_average_speed(new_speed_element.decoder_chargen, exp_value);
    // decoder tcphighports
    current_average_speed_element.decoder_tcphighports.calulate_exponential_moving_average_speed(new_speed_element.decoder_tcphighports, exp_value);
    // decoder udphighports
    current_average_speed_element.decoder_udphighports.calulate_exponential_moving_average_speed(new_speed_element.decoder_udphighports, exp_value);
    // decoder http
    current_average_speed_element.decoder_http.calulate_exponential_moving_average_speed(new_speed_element.decoder_http, exp_value);
    // decoder https
    current_average_speed_element.decoder_https.calulate_exponential_moving_average_speed(new_speed_element.decoder_https, exp_value);
    // decoder quic
    current_average_speed_element.decoder_quic.calulate_exponential_moving_average_speed(new_speed_element.decoder_quic, exp_value);

    current_average_speed_element.tcp.calulate_exponential_moving_average_speed(new_speed_element.tcp, exp_value);
    current_average_speed_element.udp.calulate_exponential_moving_average_speed(new_speed_element.udp, exp_value);
    current_average_speed_element.icmp.calulate_exponential_moving_average_speed(new_speed_element.icmp, exp_value);

    // We do calculate flow counters for all cases
    current_average_speed_element.out_flows =
        uint64_t(new_speed_element.out_flows +
                 exp_value * ((double)current_average_speed_element.out_flows - (double)new_speed_element.out_flows));

    current_average_speed_element.in_flows =
        uint64_t(new_speed_element.in_flows +
                 exp_value * ((double)current_average_speed_element.in_flows - (double)new_speed_element.in_flows));
}
