/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fcul.viegas.pcapstatistics;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.IntStream;

/**
 *
 * @author viegas
 */
public class Main {

    public static final Float PROTOCOL_NONE = 0.0f;
    public static final Float PROTOCOL_TCP = 1.0f;
    public static final Float PROTOCOL_UDP = 2.0f;
    public static final Float PROTOCOL_ICMP = 3.0f;
    public static final Float PROTOCOL_OTHER = 4.0f;

    public static NetworkPacketDTO parse(String t) throws Exception {
        String[] split = t.split(";");

        NetworkPacketDTO networkPacketDTO = new NetworkPacketDTO();

        networkPacketDTO.setTimestamp(Long.valueOf(split[0]));
        networkPacketDTO.setSourceIP(split[1]);
        networkPacketDTO.setDestinationIP(split[2]);
        String protocol = split[3];
        if (protocol.equals("TCP")) {
            networkPacketDTO.setProtocol(Main.PROTOCOL_TCP);
        } else if (protocol.equals("UDP")) {
            networkPacketDTO.setProtocol(Main.PROTOCOL_UDP);
        } else if (protocol.equals("ICMP")) {
            networkPacketDTO.setProtocol(Main.PROTOCOL_ICMP);
        } else {
            networkPacketDTO.setProtocol(Main.PROTOCOL_OTHER);
        }
        networkPacketDTO.setTimeToLive(Integer.valueOf(split[4]));
        networkPacketDTO.setUdp_source(Integer.valueOf(split[5]));
        networkPacketDTO.setUdp_dest(Integer.valueOf(split[6]));
        networkPacketDTO.setUdp_len(Integer.valueOf(split[7]));
        networkPacketDTO.setTcp_source(Integer.valueOf(split[8]));
        networkPacketDTO.setTcp_dest(Integer.valueOf(split[9]));
        networkPacketDTO.setTcp_seq(Integer.valueOf(split[10]));
        networkPacketDTO.setTcp_ack_seq(Integer.valueOf(split[11]));
        networkPacketDTO.setTcp_fin(split[12].equals("1"));
        networkPacketDTO.setTcp_syn(split[13].equals("1"));
        networkPacketDTO.setTcp_rst(split[14].equals("1"));
        networkPacketDTO.setTcp_psh(split[15].equals("1"));
        networkPacketDTO.setTcp_ack(split[16].equals("1"));
        networkPacketDTO.setTcp_urg(split[17].equals("1"));
        networkPacketDTO.setTcp_cwr(split[18].equals("1"));
        networkPacketDTO.setIcmp_type(Integer.valueOf(split[19]));
        networkPacketDTO.setIcmp_code(Integer.valueOf(split[20]));
        networkPacketDTO.setPacket_size(Integer.valueOf(split[21]));
        if (networkPacketDTO.getUdp_source() == 0) {
            networkPacketDTO.setSourcePort(networkPacketDTO.getTcp_source());
            networkPacketDTO.setDestinationPort(networkPacketDTO.getTcp_dest());
        } else {
            networkPacketDTO.setSourcePort(networkPacketDTO.getUdp_source());
            networkPacketDTO.setDestinationPort(networkPacketDTO.getUdp_dest());
        }

        return networkPacketDTO;
    }

    public static void main(String[] args) throws Exception {

        System.out.println("Openning: " + args[0]);

        int nPackets = 0;
        HashSet<String> uniqueIPs = new HashSet<>();
        HashSet<String> uniqueFlows = new HashSet<>();
        HashMap<String, HashSet> hostsFlows = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = br.readLine()) != null) {
                nPackets++;
                NetworkPacketDTO networkPacket = Main.parse(line);

                uniqueIPs.add(networkPacket.getSourceIP());
                uniqueIPs.add(networkPacket.getDestinationIP());
                uniqueFlows.add(networkPacket.getSourceIP() + networkPacket.getDestinationIP());
                if (hostsFlows.containsKey(networkPacket.getSourceIP())) {
                    HashSet<String> uniqueFlowsForHost = hostsFlows.get(networkPacket.getSourceIP());
                    uniqueFlowsForHost.add(
                            networkPacket.getDestinationIP() + networkPacket.getDestinationPort() +
                            networkPacket.getSourceIP() + networkPacket.getSourcePort()
                            );
                } else {
                    HashSet<String> uniqueFlowsForHost = new HashSet<>();
                    uniqueFlowsForHost.add(
                            networkPacket.getDestinationIP() + networkPacket.getDestinationPort() +
                            networkPacket.getSourceIP() + networkPacket.getSourcePort()
                            );
                    hostsFlows.put(networkPacket.getSourceIP(), uniqueFlowsForHost);
                }

                if (nPackets % 100000 == 0) {
                    System.out.println("Packet: " + nPackets
                            + " number of unique hosts: " + uniqueIPs.size()
                            + " number of unique flows: " + uniqueFlows.size());
                }
            }
        }
        System.out.println("FINISHED...");
        System.out.println("Packet: " + nPackets
                + " number of unique hosts: " + uniqueIPs.size()
                + " number of unique flows: " + uniqueFlows.size());

        System.out.println("Sorting flows arrays");

        Iterator it = hostsFlows.entrySet().iterator();
        int iArr[] = new int[hostsFlows.size()];
        int i = 0;
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry) it.next();
            iArr[i++] = ((HashSet<String>) pair.getValue()).size();
            it.remove();
        }
        Arrays.sort(iArr);

        System.out.println("Flows arrays sorted");
        System.out.println("Printing top 10...");
        for (i = 0; i < 10; i++) {
            System.out.println("[" + i + "]: " + iArr[iArr.length - 1 - i]);
        }

        System.out.println("Flows arrays sorted");
        System.out.println("Printing least 10...");
        for (i = 0; i < 10; i++) {
            System.out.println("[" + i + "]: " + iArr[i]);
        }
        int sum = IntStream.of(iArr).sum();
        System.out.println("Total unique flows: " + sum);

    }

}
