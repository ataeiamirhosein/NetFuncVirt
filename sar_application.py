from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches
import networkx as nx
import json
import logging
import struct
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
from timeit import default_timer
import BinaryTrie
import MultibitTrie

# Packet Classification parameters
SRC_IP = 0
DST_IP = 1
PROTO = 2
SPORT = 3
DPORT = 4
ACTION = 5

TRIE = 1  # choosing the type of trie to use: 0 for Binary, 1 for Multibit

# IP lookup parameters
IP = 0
SUBNET = 1
DPID = 2

# Topologies
TOPO = 2

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.datapaths = []
        self.switch_id = []
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.i = 0

        self.trie_root = None

        # Packet Classification initial parameters

        self.classify = {}
        self.classify["r1"] = ["195.0.0.1", "128.128.0.1", "6", "*", "1234", "allow"]
        self.classify["r2"] = ["128.128.0.1", "195.0.0.1", "6", "1234", "*", "allow"]
        self.classify["r3"] = ["195.0.0.1", "128.128.0.1", "1", "*", "*", "allow"]
        self.classify["r4"] = ["128.128.0.1", "195.0.0.1", "1", "*", "*", "allow"]
        self.classify["r5"] = ["*", "*", "*", "*", "*", "deny"]

        self.counters = {}
        self.counters["r1"] = 0
        self.counters["r2"] = 0
        self.counters["r3"] = 0
        self.counters["r4"] = 0
        self.counters["r5"] = 0

        if TOPO == 1:
            self.switch = {}
            self.switch["195.0.0.254"] = ["195.0.0.254", "8", "1"]
            self.switch["128.128.0.254"] = ["128.128.0.254", "12", "2"]
            self.switch["154.128.0.254"] = ["154.128.0.254", "16", "3"]

            self.lookup = {}
            self.lookup["195.0.0.1"] = "195.0.0.254"
            self.lookup["195.0.0.2"] = "195.0.0.254"
            self.lookup["128.128.0.1"] = "128.128.0.254"
            self.lookup["128.128.0.2"] = "128.128.0.254"
            self.lookup["154.128.0.1"] = "154.128.0.254"
            self.lookup["154.128.0.2"] = "154.128.0.254"

            self.ip_to_mac = {}
            self.ip_to_mac["195.0.0.1"] = "00:00:00:00:00:01"
            self.ip_to_mac["195.0.0.2"] = "00:00:00:00:00:02"
            self.ip_to_mac["128.128.0.1"] = "00:00:00:00:00:03"
            self.ip_to_mac["128.128.0.2"] = "00:00:00:00:00:04"
            self.ip_to_mac["154.128.0.1"] = "00:00:00:00:00:05"
            self.ip_to_mac["154.128.0.2"] = "00:00:00:00:00:06"

        elif TOPO == 2:
            self.switch = {}
            self.switch["195.0.0.254"] = ["195.0.0.254", "8", "1"]
            self.switch["128.128.0.254"] = ["128.128.0.254", "12", "2"]
            self.switch["154.128.0.254"] = ["154.128.0.254", "16", "3"]
            self.switch["197.160.0.254"] = ["197.160.0.254", "24", "4"]
            self.switch["192.168.0.254"] = ["192.168.0.254", "24", "5"]
            self.switch["192.169.0.254"] = ["192.169.0.254", "24", "6"]
            self.switch["192.170.0.254"] = ["192.170.0.254", "24", "7"]

            self.lookup = {}
            self.lookup["195.0.0.1"] = "195.0.0.254"
            self.lookup["195.0.0.2"] = "195.0.0.254"
            self.lookup["128.128.0.1"] = "128.128.0.254"
            self.lookup["154.128.0.1"] = "154.128.0.254"
            self.lookup["197.160.0.1"] = "197.160.0.254"
            self.lookup["192.168.0.1"] = "192.168.0.254"
            self.lookup["192.169.0.1"] = "192.169.0.254"
            self.lookup["192.170.0.1"] = "192.170.0.254"

            self.ip_to_mac = {}
            self.ip_to_mac["195.0.0.1"] = "00:00:00:00:00:01"
            self.ip_to_mac["195.0.0.2"] = "00:00:00:00:00:02"
            self.ip_to_mac["128.128.0.1"] = "00:00:00:00:00:03"
            self.ip_to_mac["154.128.0.1"] = "00:00:00:00:00:04"
            self.ip_to_mac["197.160.0.1"] = "00:00:00:00:00:05"
            self.ip_to_mac["192.168.0.1"] = "00:00:00:00:00:06"
            self.ip_to_mac["192.169.0.1"] = "00:00:00:00:00:07"
            self.ip_to_mac["192.170.0.1"] = "00:00:00:00:00:08"

        if TRIE == 0:  # BinaryTrie
            self.trie_root = BinaryNode.BinaryNode('0')

            for key, value in self.switch.iteritems():
                ip = value[0]
                mask = int(value[1])
                binary_address = BinaryNode.convert_in_bin(key)[:mask]  # take only the network part of address

                self.trie_root.AddChild(ip, binary_address)

            self.logger.info("BinaryTrie created")

        elif TRIE == 1:  # MultibitTrie
            self.trie_root = MultibitNode.MultibitNode()

            for entry in self.order_switch():  # order_switch is used to have and ordinated list of ips base on mask length
                ip, mask = entry
                binary_address = MultibitNode.convert_in_bin(ip)[:mask]  # take only the network part of address

                self.trie_root.AddChild(ip, binary_address)

            self.logger.info("MultibitTrie created")

    def order_switch(self):

        tuples = []
        for key, value in self.switch.iteritems():
            tuples.append((value[0], value[1]))  # append ip, mask

        return sorted(tuples, key=lambda x: x[1])

    # END OF CUSTOM CODE

    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.datapaths.append(msg.datapath)
        self.switch_id.append(msg.datapath_id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid_src = datapath.id

        # TOPOLOGY DISCOVERY------------------------------------------

        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

        # MAC LEARNING-------------------------------------------------

        self.mac_to_port.setdefault(dpid_src, {})
        self.mac_to_port.setdefault(src, {})
        self.port_to_mac.setdefault(dpid_src, {})
        self.mac_to_port[dpid_src][src] = in_port
        self.mac_to_dpid[src] = dpid_src
        self.port_to_mac[dpid_src][in_port] = src
        self.logger.info("Packet in the controller from switch: %s", dpid_src)

        # HANDLE ARP PACKETS--------------------------------------------

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = pkt.get_protocol(arp.arp)
            arp_dst_ip = arp_packet.dst_ip
            arp_src_ip = arp_packet.src_ip

            if arp_dst_ip in self.ip_to_mac:
                if arp_packet.opcode == 1:
                    # send arp reply (SAME SUBNET)
                    dstIp = arp_src_ip
                    srcIp = arp_dst_ip
                    dstMac = src
                    srcMac = self.ip_to_mac[arp_dst_ip]
                    outPort = in_port
                    opcode = 2  # arp reply packet
                    self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
            else:
                if arp_packet.opcode == 1:
                    # send arp reply (GATEWAY)
                    dstIp = arp_src_ip
                    srcIp = arp_dst_ip
                    dstMac = src
                    srcMac = self.port_to_mac[dpid_src][in_port]
                    outPort = in_port
                    opcode = 2  # arp reply packet
                    self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

        # HANDLE IP PACKETS-----------------------------------------------

        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip4_pkt:
            src_ip = ip4_pkt.src
            dst_ip = ip4_pkt.dst
            proto = str(ip4_pkt.proto)
            sport = "0"
            dport = "0"
            if proto == "6":
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                sport = str(tcp_pkt.src_port)
                dport = str(tcp_pkt.dst_port)

            if proto == "17":
                udp_pkt = pkt.get_protocol(udp.udp)
                sport = str(udp_pkt.src_port)
                dport = str(udp_pkt.dst_port)

            self.logger.info("Packet from the switch: %s, source IP: %s, destination IP: %s, From the port: %s",
                             dpid_src, src_ip, dst_ip, in_port)

            # PACKET CLASSIFICATION FUNCTION: it returns action: "allow" or "deny"
         
            action_rule = "allow"

            if action_rule == "allow":
                # IP LOOKUP FUNCTION: it is zero if it didn't find a solution
            
                destination_switch_IP = self.binary_search(dst_ip)

                if destination_switch_IP != "0":
                    datapath_dst = get_datapath(self, int(self.switch[destination_switch_IP][DPID]))
                    dpid_dst = datapath_dst.id
                    self.logger.info(" --- Destination present on switch: %s", dpid_dst)

                    # Shortest path computation
                    path = nx.shortest_path(self.net, dpid_src, dpid_dst)
                    self.logger.info(" --- Shortest path: %s", path)

                    if len(path) == 1:
                        In_Port = self.mac_to_port[dpid_src][src]
                        Out_Port = self.mac_to_port[dpid_dst][dst]
                        actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
                        actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
                        match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst)
                        self.add_flow(datapath, 1, match_1, actions_1)

                        actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
                        data = msg.data
                        pkt = packet.Packet(data)
                        eth = pkt.get_protocols(ethernet.ethernet)[0]
                        # self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
                        pkt.serialize()
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                            actions=actions, data=pkt.data)
                        datapath.send_msg(out)

                    elif len(path) == 2:
                        path_port = self.net[path[0]][path[1]]['port']
                        actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
                        data = msg.data
                        pkt = packet.Packet(data)
                        eth = pkt.get_protocols(ethernet.ethernet)[0]
                        eth.src = self.ip_to_mac[src_ip]
                        eth.dst = self.ip_to_mac[dst_ip]
                        # self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
                        pkt.serialize()
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                            actions=actions, data=pkt.data)
                        datapath.send_msg(out)

                    elif len(path) > 2:
                        # Add flows in the middle of the network path
                        for i in range(1, len(path) - 1):
                            In_Port = self.net[path[i]][path[i - 1]]['port']
                            Out_Port = self.net[path[i]][path[i + 1]]['port']
                            dp = get_datapath(self, path[i])

                            actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port)]
                            match_1 = parser.OFPMatch(in_port=In_Port, eth_type=0x0800, ipv4_src=src_ip,
                                                      ipv4_dst=dst_ip)
                            self.add_flow(dp, 1, match_1, actions_1)

                        path_port = self.net[path[0]][path[1]]['port']
                        actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
                        data = msg.data
                        pkt = packet.Packet(data)
                        eth = pkt.get_protocols(ethernet.ethernet)[0]
                        # change the mac address of packet
                        eth.src = self.ip_to_mac[src_ip]
                        eth.dst = self.ip_to_mac[dst_ip]
                        # self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
                        pkt.serialize()
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                            actions=actions, data=pkt.data)
                        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

    # CUSTOM CODE
    def binary_search(self, dst_ip):

        destination_switch_ip = ''

        if TRIE == 0:
            self.logger.info(" --- IP Lookup with Binary Trie")
            binary_dst = BinaryNode.convert_in_bin(dst_ip)
            start = default_timer()
            destination_switch_ip = self.trie_root.Lookup(binary_dst)
            end = default_timer() - start
            self.logger.info("Binary trie returned: " + str(destination_switch_ip))
            self.logger.info("time elapsed: " + str(end*1000) + "ms")

        elif TRIE == 1:
            self.logger.info(" --- IP Lookup with Multibit Trie")
            binary_dst = MultibitNode.convert_in_bin(dst_ip)
            start = default_timer()
            destination_switch_ip = self.trie_root.Lookup(binary_dst, "0")
            end = default_timer() - start
            self.logger.info("Multibit trie returned: " + str(destination_switch_ip))
            self.logger.info("time elapsed: " + str(end*1000) + "ms")

        if destination_switch_ip != '':
            return destination_switch_ip
        else:
            return "0"
    # END OF CUSTOM CODE

    def linear_search(self, dst_ip):
        self.logger.info(" --- IP address Lookup")
        if dst_ip in self.lookup:
            destination_switch_IP = self.lookup[dst_ip]
            return destination_switch_IP
        else:
            destination_switch_IP = "0"
            return destination_switch_IP

    def linear_classification(self, src_ip, dst_ip, proto, sport, dport):
        action = "deny"
        self.logger.info(" --- Packet classification")

        # check matching rule
        for rule in sorted(self.classify):
            match = self.classify[rule]
            if (match[SRC_IP] == src_ip or match[SRC_IP] == "*") and \
                    (match[DST_IP] == dst_ip or match[DST_IP] == "*") and \
                    (match[PROTO] == proto or match[PROTO] == "*") and \
                    (match[SPORT] == sport or match[SPORT] == "*") and \
                    (match[DPORT] == dport or match[DPORT] == "*"):
                self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[ACTION]))
                action = match[ACTION]
                self.counters[rule] = self.counters[rule] + 1
                return action

        return action

app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')
