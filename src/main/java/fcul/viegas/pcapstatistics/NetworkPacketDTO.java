/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fcul.viegas.pcapstatistics;

/**
 *
 * @author viegas
 */
public class NetworkPacketDTO {

    private Long timestamp;

    private String sourceIP;
    private String destinationIP;
    private Float protocol;
    private Integer timeToLive;
    private Integer sourcePort;
    private Integer destinationPort;

    //udp
    private Integer udp_source;
    private Integer udp_dest;
    private Integer udp_len;

    //tcp
    private Integer tcp_source;
    private Integer tcp_dest;
    private Integer tcp_seq;
    private Integer tcp_ack_seq;

    private Boolean tcp_fin;
    private Boolean tcp_syn;
    private Boolean tcp_rst;
    private Boolean tcp_psh;
    private Boolean tcp_ack;
    private Boolean tcp_urg;
    private Boolean tcp_cwr;

    //icmp
    private Integer icmp_type;
    private Integer icmp_code;

    private Integer packet_size;

    public Boolean getTcp_cwr() {
        return tcp_cwr;
    }

    public void setTcp_cwr(Boolean tcp_cwr) {
        this.tcp_cwr = tcp_cwr;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public Integer getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(Integer timeToLive) {
        this.timeToLive = timeToLive;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public void setDestinationIP(String destinationIP) {
        this.destinationIP = destinationIP;
    }

    public Float getProtocol() {
        return protocol;
    }

    public void setProtocol(Float protocol) {
        this.protocol = protocol;
    }

    public Integer getUdp_source() {
        return udp_source;
    }

    public void setUdp_source(Integer udp_source) {
        this.udp_source = udp_source;
    }

    public Integer getUdp_dest() {
        return udp_dest;
    }

    public void setUdp_dest(Integer udp_dest) {
        this.udp_dest = udp_dest;
    }

    public Integer getUdp_len() {
        return udp_len;
    }

    public void setUdp_len(Integer udp_len) {
        this.udp_len = udp_len;
    }

    public Integer getTcp_source() {
        return tcp_source;
    }

    public void setTcp_source(Integer tcp_source) {
        this.tcp_source = tcp_source;
    }

    public Integer getTcp_dest() {
        return tcp_dest;
    }

    public void setTcp_dest(Integer tcp_dest) {
        this.tcp_dest = tcp_dest;
    }

    public Integer getTcp_seq() {
        return tcp_seq;
    }

    public void setTcp_seq(Integer tcp_seq) {
        this.tcp_seq = tcp_seq;
    }

    public Integer getTcp_ack_seq() {
        return tcp_ack_seq;
    }

    public void setTcp_ack_seq(Integer tcp_ack_seq) {
        this.tcp_ack_seq = tcp_ack_seq;
    }

    public Boolean getTcp_fin() {
        return tcp_fin;
    }

    public void setTcp_fin(Boolean tcp_fin) {
        this.tcp_fin = tcp_fin;
    }

    public Boolean getTcp_syn() {
        return tcp_syn;
    }

    public void setTcp_syn(Boolean tcp_syn) {
        this.tcp_syn = tcp_syn;
    }

    public Boolean getTcp_rst() {
        return tcp_rst;
    }

    public void setTcp_rst(Boolean tcp_rst) {
        this.tcp_rst = tcp_rst;
    }

    public Boolean getTcp_psh() {
        return tcp_psh;
    }

    public void setTcp_psh(Boolean tcp_psh) {
        this.tcp_psh = tcp_psh;
    }

    public Boolean getTcp_ack() {
        return tcp_ack;
    }

    public void setTcp_ack(Boolean tcp_ack) {
        this.tcp_ack = tcp_ack;
    }

    public Boolean getTcp_urg() {
        return tcp_urg;
    }

    public void setTcp_urg(Boolean tcp_urg) {
        this.tcp_urg = tcp_urg;
    }

    public Integer getIcmp_type() {
        return icmp_type;
    }

    public void setIcmp_type(Integer icmp_type) {
        this.icmp_type = icmp_type;
    }

    public Integer getIcmp_code() {
        return icmp_code;
    }

    public void setIcmp_code(Integer icmp_code) {
        this.icmp_code = icmp_code;
    }

    public Integer getPacket_size() {
        return packet_size;
    }

    public void setPacket_size(Integer packet_size) {
        this.packet_size = packet_size;
    }

    public String toString() {
        String ret = "(";

        ret = ret + "timestamp:" + this.getTimestamp();
        ret = ret + ", sourceip:" + this.getSourceIP();
        ret = ret + ", destinationip:" + this.getDestinationIP();
        ret = ret + ", protocol:" + this.getProtocol();
        ret = ret + ", timetolive:" + this.getTimeToLive();
        ret = ret + ", udp_source:" + this.getUdp_source();
        ret = ret + ", udp_destination:" + this.getUdp_dest();
        ret = ret + ", udp_len:" + this.getUdp_len();
        ret = ret + ", tcp_source:" + this.getTcp_source();
        ret = ret + ", tcp_destination:" + this.getTcp_dest();
        ret = ret + ", tcp_seq:" + this.getTcp_seq();
        ret = ret + ", tcp_ack:" + this.getTcp_ack_seq();
        ret = ret + ", tcp_flag_fin:" + this.getTcp_fin();
        ret = ret + ", tcp_flag_syn:" + this.getTcp_syn();
        ret = ret + ", tcp_flag_rst:" + this.getTcp_rst();
        ret = ret + ", tcp_flag_psh:" + this.getTcp_psh();
        ret = ret + ", tcp_flag_ack:" + this.getTcp_ack();
        ret = ret + ", tcp_flag_urg:" + this.getTcp_urg();
        ret = ret + ", icmp_type:" + this.getIcmp_type();
        ret = ret + ", icmp_code:" + this.getIcmp_code();
        ret = ret + ", packet_size:" + this.getPacket_size();

        ret = ret + ")";
        return ret;
    }

}
