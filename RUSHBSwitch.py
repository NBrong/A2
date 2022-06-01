import socket
import sys
import struct
import threading
import math
import time

RECV_SIZE = 55296
LOCAL_HOST = "127.0.0.1"
TIME_OUT = 5
DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00

lock = threading.Lock()


def fetch_prefix(des_ip, ip_list):
    d_ip = int(int_to_ip(des_ip).split('.')[0])
    max_ip = None
    max_fetch = 0
    for ip in ip_list:
        check_prefix = int(int_to_ip(ip).split('.')[0])
        d_len = len(str(bin(d_ip))[2:])
        check_len = len(str(bin(check_prefix))[2:])
        for i in range(min(d_len, check_len)):
            if str(bin(d_ip))[2:][i] != str(bin(check_prefix))[2:][i]:
                if i > max_fetch:
                    max_ip = ip
                    max_fetch = i
                break
    return max_ip


def bytes_to_ip(data):
    return int_to_ip(int.from_bytes(data, byteorder='big'))


def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size=11):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def new_tcp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def new_udp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def int_to_bytes(integer, size):
    return integer.to_bytes(size, byteorder='big')


def calculate_distance(s_x, s_y, c_x, c_y):
    distance = math.sqrt(((s_x - c_x) ** 2) + ((s_y - c_y) ** 2))
    return round(distance)


def make_packet(source_ip, destination_ip, offset, mode, assigned_ip=None, data=None,
                l_x=None, l_y=None, target_ip=None, distance=None):
    pkt = bytearray()
    pkt += int_to_bytes(ip_to_int(source_ip), 4)
    pkt += int_to_bytes(ip_to_int(destination_ip), 4)
    pkt += int_to_bytes(offset, 3)
    pkt += int_to_bytes(mode, 1)
    if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
        pkt += int_to_bytes(ip_to_int(assigned_ip), 4)
    if mode == DATA:
        pkt += data.encode('utf-8')
    if mode == LOCATION:
        pkt += int_to_bytes(l_x, 2)
        pkt += int_to_bytes(l_y, 2)
    if mode == DISTANCE:
        pkt += int_to_bytes(ip_to_int(target_ip), 4)
        pkt += int_to_bytes(distance, 4)
    if mode == MORE_FRAG:
        pkt += data
    if mode == END_FRAG:
        pkt += data
    return pkt


def split_packet(source_ip, des_ip, packet):
    result = []
    if len(packet) <= 1500:
        result.append(packet)
        return result
    index = 0
    data = packet[12:]

    while index < len(data) - 1488:
        fragmentation = data[index:index + 1488]
        fra_packet = make_packet(source_ip, des_ip, 0x000000, MORE_FRAG, data=fragmentation)
        result.append(fra_packet)
    final_packet = make_packet(source_ip, des_ip, index, END_FRAG, data=data[index:index + 1488])
    result.append(final_packet)
    return result


class RUSHBSwitchLocal:

    def __init__(self, serve_ip, subnet, l_x, l_y):
        self.serve_ip = serve_ip
        self.subnet = subnet
        self.l_x = int(l_x)
        self.l_y = int(l_y)
        self.adapters = {}
        self.adapters_data = {}
        self.udp_socket = new_udp_socket(0)
        self.tcp_links = {}
        self.tcp_data = {}
        self.distance_table = {}
        self.shortest_distance_table = {}
        self.max_ips = 2 ** (32 - int(subnet)) - 2
        self.send_message = ''
        self.recv_message = ''

    def run(self):
        port = str(self.udp_socket.getsockname()[1])
        print(port, flush=True)
        udp = threading.Thread(target=self.listen_udp)
        udp.start()
        tcp = threading.Thread(target=self.take_input)
        tcp.start()

    def listen_udp(self):
        while True:
            self.receiving_udp()

    def get_ass_ip(self):
        if len(self.adapters) == 0:
            ip = ip_to_int(self.serve_ip) + 1
        else:
            inverse = [(key, value) for key, value in self.adapters.items()]
            ip = max(inverse)[0] + 1
        return int_to_ip(ip)

    def broadcast(self, recv_packet, target_ip):
        # print("Broadcast target_ip:" + str(target_ip), flush=True)
        int_source_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
        for link in self.tcp_links.keys():
            if link != int_source_ip and \
                    link != int.from_bytes(recv_packet.destinationIP, byteorder='big') and \
                    link != target_ip:
                tcp_client = self.tcp_links[link]
                # calculate the distance between neighbor and new link through self
                sum_distance = tcp_client.distance + self.distance_table[int_source_ip].possible_switch[target_ip]
                broadcast_packet = make_packet(self.tcp_links[link].client_ip, int_to_ip(link),
                                               0x000000, DISTANCE, target_ip=int_to_ip(target_ip),
                                               distance=sum_distance)
                # print("Send distance broadcast packet", flush=True)
                tcp_client.client.send(broadcast_packet)

    def update_shortest(self, recv_packet, target_ip, client, local_distance=None):
        """
        recv_packet must be distance packet.
        """

        if local_distance is not None:
            new_distance = local_distance
            # print("New distance(typed) = " + str(new_distance), flush=True)
        else:
            new_distance = int.from_bytes(recv_packet.distance, byteorder='big')
            # print("New distance(from packet) = " + str(new_distance), flush=True)
        if target_ip in self.shortest_distance_table.keys():
            for distance in self.shortest_distance_table[target_ip]:
                if new_distance < distance.distance:
                    self.shortest_distance_table[target_ip] = [Distance(client,
                                                                        int.from_bytes(recv_packet.sourceIP,
                                                                                       byteorder='big'), new_distance)]
                    # print("Replace shortest table for " + str(int_to_ip(target_ip)), flush=True)
                    break
                elif new_distance == distance.distance:
                    self.shortest_distance_table[target_ip].append(Distance(client,
                                                                            int.from_bytes(recv_packet.sourceIP,
                                                                                           byteorder='big'),
                                                                            new_distance))
                    # print("update same distance shortest table for " + str(int_to_ip(target_ip)), flush=True)
                    break
        else:
            self.shortest_distance_table[target_ip] = [Distance(client,
                                                                int.from_bytes(recv_packet.sourceIP, byteorder='big'),
                                                                new_distance)]
            # print("update a new record in shortest table for " + str(int_to_ip(target_ip)), flush=True)

    def receiving_udp(self):
        data, address = self.udp_socket.recvfrom(RECV_SIZE)
        recv_packet = LocalPacket(data)
        # sys.stdout.write("Receive:" + "\n")
        # sys.stdout.flush()
        lock.acquire()
        # print(data)
        lock.release()
        if recv_packet.real_mode == DISCOVERY:
            if len(self.adapters) == self.max_ips:  # If the subnet amount has been run out, ignore new adapter connect.
                return
            return_packet = make_packet(self.serve_ip, "0", 0x000000, OFFER, assigned_ip=self.get_ass_ip())
            self.udp_socket.sendto(return_packet, address)
        elif recv_packet.real_mode == REQUEST:
            return_packet = make_packet(self.serve_ip,
                                        int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')),
                                        0x000000,
                                        ACKNOWLEDGE,
                                        assigned_ip=int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
            self.udp_socket.sendto(return_packet, address)
            # Add a new adapter connection in dictionary
            self.adapters[ip_to_int(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))] = address[1]
            # print("Add one new adapter: " + str(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big'))))
        elif recv_packet.real_mode == DATA:
            # lock acquire ---------------------------------------------------------------------------------#
            lock.acquire()
            # print("Data packet:" + bytes_to_ip(recv_packet.destinationIP), flush=True)
            packet_list = split_packet(bytes_to_ip(recv_packet.sourceIP), bytes_to_ip(recv_packet.destinationIP), data)
            # print("packet_list:" + str(packet_list), flush=True)
            # If ip in the shortest path
            if int.from_bytes(recv_packet.destinationIP, byteorder='big') in self.shortest_distance_table.keys():
                # print("Data source ip in shortest table", flush=True)
                shortest_know_path = self.shortest_distance_table[
                    int.from_bytes(recv_packet.destinationIP, byteorder='big')]

                if len(shortest_know_path) == 1:
                    tcp_link = shortest_know_path[0].connect_switch
                    if tcp_link in self.tcp_data.keys():
                        self.tcp_data[tcp_link].data.extend(packet_list)
                        if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                            self.send_data_to_tcp(tcp_link)
                        else:
                            source_ip = self.tcp_links[tcp_link].client_ip
                            self.send_tcp_query(tcp_link, source_ip)
                    else:
                        self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                        source_ip = self.tcp_links[tcp_link].client_ip
                        self.send_tcp_query(tcp_link, source_ip)

                elif len(shortest_know_path) == 2:
                    ip_list = [shortest_know_path[0].connect_switch, shortest_know_path[1].connect_switch]
                    tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                    if tcp_link in self.tcp_data.keys():
                        self.tcp_data[tcp_link].data.extend(packet_list)
                        if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                            self.send_data_to_tcp(tcp_link)
                        else:
                            source_ip = self.tcp_links[tcp_link].client_ip
                            self.send_tcp_query(tcp_link, source_ip)
                    else:
                        self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                        source_ip = self.tcp_links[tcp_link].client_ip
                        self.send_tcp_query(tcp_link, source_ip)
            # If No record in the shortest path
            else:
                ip_list = []
                for link in self.tcp_links.keys():
                    ip_list.append(link)
                tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        source_ip = self.tcp_links[tcp_link].client_ip
                        self.send_tcp_query(tcp_link, source_ip)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    source_ip = self.tcp_links[tcp_link].client_ip
                    self.send_tcp_query(tcp_link, source_ip)
            # lock release---------------------------------------------------------------------------------<>
            lock.release()
        elif recv_packet.real_mode == AVAILABLE:
            # lock-------------------------------------------------------------------------------------------#
            lock.acquire()
            adapter_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
            adapter_data = self.adapters_data[adapter_ip]
            adapter_data.time = time.time()
            for data in adapter_data.data:
                self.udp_socket.sendto(data, self.adapters[adapter_ip])
            # clear adapter data
            adapter_data.data.clear()
            # Release lock---------------------------------------------------------------------------------<>
            lock.release()

    def send_data_to_tcp(self, tcp_ip):
        send_socket = self.tcp_links[tcp_ip].client
        for packet in self.tcp_data[tcp_ip].data:
            send_socket.sendall(packet)
        self.tcp_data[tcp_ip].data.clear()

    def send_data_to_udp(self, adapter_ip):
        adapter_data = self.adapters_data[adapter_ip]
        adapter_data.time = time.time()
        for data in adapter_data.data:
            self.udp_socket.sendto(data, self.adapters[adapter_ip])
        # clear adapter data
        adapter_data.data.clear()

    def send_query(self, adapter_ip):

        query_packet = make_packet(self.serve_ip, adapter_ip, 0x000000, QUERY)
        self.udp_socket.sendto(query_packet, (LOCAL_HOST, self.adapters[adapter_ip]))

    def send_tcp_query(self, tcp_ip, source_ip):
        query_packet = make_packet(source_ip, int_to_ip(tcp_ip), 0x000000, QUERY)
        tcp_socket = self.tcp_links[tcp_ip].client
        tcp_socket.sendall(query_packet)

    def take_input(self):
        """
        Take command from stdin. Acceptable command is 'connect'
        """
        # time.sleep(0.5)
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                return
            else:
                self.connect_command(user_input)

    def connect_command(self, user_input):
        user_input_split = user_input.split(maxsplit=2)  # prevent splitting data
        if len(user_input_split) != 2:
            return
        command = user_input_split[0]
        port = user_input_split[1]
        try:
            port = int(port)
        except TypeError as e:
            return
        # Create packet and send
        if command in 'connect' and isinstance(port, int):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((LOCAL_HOST, port))
            discovery_packet = make_packet("0", "0", 0x000000, DISCOVERY, assigned_ip="0")
            client.send(discovery_packet)
            # print("Send discovery____________", flush=True)
            # print(discovery_packet, flush=True)
            tcp_listen = threading.Thread(target=self.tcp_client_listening, args=(client,))
            tcp_listen.start()

    def tcp_client_listening(self, client=new_tcp_socket(0)):
        while True:
            data = client.recv(4096)
            recv_packet = GlobalPacket(data)
            # lock.acquire()
            # print(recv_packet)
            # lock.release()
            if recv_packet.real_mode == OFFER:
                return_packet = make_packet("0", int_to_ip(int.from_bytes(recv_packet.sourceIP, byteorder='big')),
                                            0x000000, REQUEST,
                                            assigned_ip=int_to_ip(
                                                int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
                client.send(return_packet)

            elif recv_packet.real_mode == ACKNOWLEDGE:
                # Lock tcp_links----------------------#
                lock.acquire()
                self.tcp_links[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = TCPLink(client,
                                                                                                bytes_to_ip(
                                                                                                    recv_packet.assigned_ip),
                                                                                                None)
                return_packet = make_packet(bytes_to_ip(recv_packet.assigned_ip),
                                            bytes_to_ip(recv_packet.sourceIP),
                                            0x000000,
                                            LOCATION,
                                            l_x=self.l_x,
                                            l_y=self.l_y)
                client.send(return_packet)
                # Release tcp_links
                lock.release()

            elif recv_packet.real_mode == LOCATION:
                # Lock tcp_links-----------------------#
                lock.acquire()
                int_source_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
                distance = calculate_distance(recv_packet.l_x, recv_packet.l_y, self.l_x, self.l_y)
                self.tcp_links[int_source_ip].distance = distance
                possible_link = {int_source_ip: distance}
                self.distance_table[int_source_ip] = PossibleDistance(client, possible_link)
                self.update_shortest(recv_packet, int_source_ip, client, local_distance=distance)
                self.broadcast(recv_packet, int_source_ip)
                lock.release()

            elif recv_packet.real_mode == DISTANCE:
                # print("Distance packet received......" + str(
                #     int.from_bytes(recv_packet.distance, byteorder='big')) + ':' +
                #       str(int.from_bytes(recv_packet.target_ip, byteorder='big')),
                #       flush=True)
                if int.from_bytes(recv_packet.distance, byteorder='big') <= 1000:
                    # Lock tcp_links------------------------------------------------------------------#
                    lock.acquire()
                    possible_links = self.distance_table[
                        int.from_bytes(recv_packet.sourceIP, byteorder='big')].possible_switch
                    if int.from_bytes(recv_packet.target_ip, byteorder='big') in possible_links.keys():
                        if possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] >= int.from_bytes(
                                recv_packet.distance, byteorder='big'):
                            possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                                recv_packet.distance, byteorder='big')
                            # Broadcast distance
                            self.broadcast(recv_packet,
                                           target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                            # Update shortest distance
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                                 client)
                    else:
                        possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                            recv_packet.distance, byteorder='big')
                        # Broadcast distance
                        self.broadcast(recv_packet, target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                        # Update shortest distance
                        self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                             client)
                    # Release tcp_links----------------------------------------------------------------<>
                    lock.release()

            elif recv_packet.real_mode == DATA:
                lock.acquire()
                packet_list = [data]
                # If the destination is one of adapters
                if int.from_bytes(recv_packet.destinationIP, byteorder='big') in self.adapters.keys():
                    adapter_ip = int.from_bytes(recv_packet.destinationIP, byteorder='big')
                    if adapter_ip in self.adapters_data.keys():
                        self.adapters_data[adapter_ip].data.append(recv_packet)
                        if time.time() - self.adapters_data[adapter_ip].check_time <= 5:
                            self.send_data_to_udp(adapter_ip)
                        else:
                            self.send_query(adapter_ip)
                    else:
                        self.adapters_data[adapter_ip] = Data(time.time(), [recv_packet])
                # If here is a record in the shortest path
                elif int.from_bytes(recv_packet.destinationIP, byteorder='big') in self.shortest_distance_table.keys():
                    shortest_know_path = self.shortest_distance_table[
                        int.from_bytes(recv_packet.destinationIP, byteorder='big')]

                    if len(shortest_know_path) == 1:
                        tcp_link = shortest_know_path[0].connect_switch
                        if tcp_link in self.tcp_data.keys():
                            self.tcp_data[tcp_link].data.extend(packet_list)
                            if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                                self.send_data_to_tcp(tcp_link)
                            else:
                                source_ip = self.tcp_links[tcp_link].client_ip
                                self.send_tcp_query(tcp_link, source_ip)
                        else:
                            self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                            source_ip = self.tcp_links[tcp_link].client_ip
                            self.send_tcp_query(tcp_link, source_ip)

                    elif len(shortest_know_path) == 2:
                        ip_list = [shortest_know_path[0].connect_switch, shortest_know_path[1].connect_switch]
                        tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                        if tcp_link in self.tcp_data.keys():
                            self.tcp_data[tcp_link].data.extend(packet_list)
                            if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                                self.send_data_to_tcp(tcp_link)
                            else:
                                source_ip = self.tcp_links[tcp_link].client_ip
                                self.send_tcp_query(tcp_link, source_ip)
                        else:
                            self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                            source_ip = self.tcp_links[tcp_link].client_ip
                            self.send_tcp_query(tcp_link, source_ip)
                # If No record in the shortest path
                else:
                    ip_list = []
                    for link in self.tcp_links.keys():
                        ip_list.append(link)
                    tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                    if tcp_link in self.tcp_data.keys():
                        self.tcp_data[tcp_link].data.extend(packet_list)
                        if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                            self.send_data_to_tcp(tcp_link)
                        else:
                            source_ip = self.tcp_links[tcp_link].client_ip
                            self.send_tcp_query(tcp_link, source_ip)
                    else:
                        self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                        source_ip = self.tcp_links[tcp_link].client_ip
                        self.send_tcp_query(tcp_link, source_ip)
                lock.release()
            elif recv_packet.real_mode == AVAILABLE:
                # print("Receive  AVAILABLE", flush=True)
                # lock tcp_links----------------------------------------------------------------#
                lock.acquire()
                self.tcp_data[int.from_bytes(recv_packet.sourceIP, byteorder='big')].check_time = time.time()
                # print(self.tcp_data[int.from_bytes(recv_packet.sourceIP, byteorder='big')].data, flush=True)
                self.send_data_to_tcp(int.from_bytes(recv_packet.sourceIP, byteorder='big'))
                # Release tcp_links----------------------------------------------------------------<>
                lock.release()
            elif recv_packet.real_mode == QUERY:
                lock.acquire()
                available_packet = make_packet(bytes_to_ip(recv_packet.destinationIP),
                                               bytes_to_ip(recv_packet.sourceIP), 0x000000, AVAILABLE)
                client.sendall(available_packet)
                lock.release()


class RUSHBSwitchGlobal:
    def __init__(self, serve_ip, subnet, l_x, l_y):
        self.serve_ip = serve_ip
        self.subnet = subnet
        self.l_x = int(l_x)
        self.l_y = int(l_y)
        self.listen_socket = new_tcp_socket(0)
        self.listen_socket.listen(5)
        self.server_links = {}
        self.clients_ips = {}
        self.clients_distance = {}
        self.distance_table = {}
        self.shortest_distance_table = {}
        self.tcp_data = {}
        self.max_ips = 2 ** (32 - int(subnet)) - 2

        self.send_message = ''
        self.recv_message = ''

    def run(self):
        port = str(self.listen_socket.getsockname()[1])
        print(port, flush=True)
        tcp_client = threading.Thread(target=self.take_input)
        tcp_client.start()
        tcp_server = threading.Thread(target=self.receiving_tcp)
        tcp_server.start()

    def get_ass_ip(self):
        if len(self.clients_ips) == 0:
            ip = ip_to_int(self.serve_ip) + 1
        else:
            inverse = [(key, value) for key, value in self.clients_ips.items()]
            # print("get assigned ip", flush=True)
            # print(inverse, flush=True)
            ip = max(inverse)[0] + 1
        return int_to_ip(ip)

    def broadcast(self, recv_packet, target_ip):
        # print("Neighbors:", flush=True)
        # print(self.server_links.keys(), flush=True)
        # print(self.clients_distance.keys(), flush=True)
        # print("Broadcast target_ip:" + str(target_ip), flush=True)
        int_source_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
        for link in self.server_links.keys():
            if link != int_source_ip and \
                    link != int.from_bytes(recv_packet.destinationIP, byteorder='big') and \
                    link != target_ip:
                tcp_client = self.server_links[link]
                # calculate the distance between neighbor and new link through self
                sum_distance = tcp_client.distance + self.distance_table[int_source_ip].possible_switch[target_ip]
                broadcast_packet = make_packet(self.server_links[link].client_ip, int_to_ip(link),
                                               0x000000, DISTANCE, target_ip=int_to_ip(target_ip),
                                               distance=sum_distance)
                # print("send broadcast packet", flush=True)
                tcp_client.client.send(broadcast_packet)
        for link in self.clients_distance.keys():
            if link != int_source_ip and \
                    link != int.from_bytes(recv_packet.destinationIP, byteorder='big') and \
                    link != target_ip:
                tcp_client = self.clients_distance[link]
                # calculate the distance between neighbor and new link through self
                sum_distance = tcp_client.distance + self.distance_table[int_source_ip].possible_switch[target_ip]
                broadcast_packet = make_packet(self.serve_ip, int_to_ip(link),
                                               0x000000, DISTANCE, target_ip=int_to_ip(target_ip),
                                               distance=sum_distance)
                # print("send broadcast packet for my client", flush=True)
                # print(tcp_client.client)
                tcp_client.client.sendall(broadcast_packet)

    def update_shortest(self, recv_packet, target_ip, client, local_distance=None, connect_switch_ip=None):
        """
        recv_packet must be distance packet.
        """
        if local_distance is not None:
            new_distance = local_distance
            # print("New distance(typed) = " + str(new_distance), flush=True)
        else:
            new_distance = int.from_bytes(recv_packet.distance, byteorder='big')
            # print("New distance(from packet) = " + str(new_distance), flush=True)
        if connect_switch_ip is not None:
            short_path_direction = connect_switch_ip
        else:
            short_path_direction = int.from_bytes(recv_packet.sourceIP, byteorder='big')
        if target_ip in self.shortest_distance_table.keys():
            for distance in self.shortest_distance_table[target_ip]:
                if new_distance < distance.distance:
                    self.shortest_distance_table[target_ip] = [Distance(client,
                                                                        short_path_direction, new_distance)]
                    # print("Replace shortest table for " + str(target_ip), flush=True)
                    break
                elif new_distance == distance.distance:
                    self.shortest_distance_table[target_ip].append(Distance(client,
                                                                            short_path_direction,
                                                                            new_distance))
                    # print("update same in shortest table for " + str(target_ip), flush=True)
                    break
        else:
            self.shortest_distance_table[target_ip] = [Distance(client,
                                                                short_path_direction,
                                                                new_distance)]
            # print("update a new record in shortest table for  " + str(target_ip), flush=True)

    def send_data_to_tcp(self, tcp_ip):
        send_socket = self.get_socket(tcp_ip)
        for packet in self.tcp_data[tcp_ip].data:
            send_socket.sendall(packet)
        self.tcp_data[tcp_ip].data.clear()

    def get_socket(self, tcp_ip):
        send_socket = None
        if tcp_ip in self.server_links.keys():
            send_socket = self.server_links[tcp_ip].client
        elif tcp_ip in self.clients_ips.keys():
            send_socket = self.clients_ips[tcp_ip]
        return send_socket

    def send_tcp_query(self, tcp_ip):
        source_ip = None
        if tcp_ip in self.server_links.keys():
            source_ip = self.server_links[tcp_ip].client_ip
        elif tcp_ip in self.clients_ips.keys():
            source_ip = self.serve_ip
        query_packet = make_packet(source_ip, int_to_ip(tcp_ip), 0x000000, QUERY)
        send_socket = self.get_socket(tcp_ip)
        send_socket.sendall(query_packet)

    def receiving_tcp(self):
        while True:
            new_socket, address = self.listen_socket.accept()
            tcp_server = threading.Thread(target=self.tcp_server, args=(new_socket,))
            tcp_server.start()

    def tcp_server(self, serve_socket=new_tcp_socket(0)):
        while True:
            data = serve_socket.recv(4096)
            recv_packet = GlobalPacket(data)
            # lock.acquire()
            # print(recv_packet.real_mode)
            # lock.release()
            if recv_packet.real_mode == DISCOVERY:
                if len(self.clients_ips) == self.max_ips:  # If the subnet amount has been run out, ignore new adapter connect.
                    return
                return_packet = make_packet(self.serve_ip, "0", 0x000000, OFFER, assigned_ip=self.get_ass_ip())
                serve_socket.sendall(return_packet)

            elif recv_packet.real_mode == REQUEST:
                # Lock tcp_links-----------------------------------------------------------------#
                lock.acquire()
                return_packet = make_packet(self.serve_ip,
                                            int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')),
                                            0x000000,
                                            ACKNOWLEDGE,
                                            assigned_ip=int_to_ip(
                                                int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
                serve_socket.sendall(return_packet)
                # Add a new adapter connection in dictionary
                self.clients_ips[
                    ip_to_int(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))] = serve_socket
                # print("Add one new client: " + str(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big'))),
                #       flush=True)
                # Release tcp link--------------------------------------------------------------------------<>
                lock.release()

            elif recv_packet.real_mode == LOCATION:
                # Lock tcp_links--------------------------------------------------------------------#
                lock.acquire()
                distance = calculate_distance(self.l_x, self.l_y, recv_packet.l_x, recv_packet.l_y)
                self.clients_distance[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = Distance(serve_socket,
                                                                                                        int.from_bytes(
                                                                                                            recv_packet.sourceIP,
                                                                                                            byteorder='big'),
                                                                                                        distance)
                # print("New switch distance: " + str(distance), flush=True)
                possible_link = {int.from_bytes(recv_packet.sourceIP, byteorder='big'): distance}
                self.distance_table[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = PossibleDistance(
                    serve_socket, possible_link)
                self.update_shortest(recv_packet, int.from_bytes(recv_packet.sourceIP, byteorder='big'), serve_socket,
                                     local_distance=distance)
                # self.shortest_distance_table[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = [
                #     Distance(serve_socket,
                #              int.from_bytes(recv_packet.sourceIP, byteorder='big'),
                #              distance)]
                return_packet = make_packet(self.serve_ip, bytes_to_ip(recv_packet.sourceIP), 0x000000, LOCATION,
                                            l_x=self.l_x,
                                            l_y=self.l_y)
                serve_socket.sendall(return_packet)
                # Release tcp link----------------------------------------------------------------------<>
                lock.release()

            elif recv_packet.real_mode == DISTANCE:
                # print("Distance packet received......" + str(
                #     int.from_bytes(recv_packet.distance, byteorder='big')) + ':' +
                #       str(int.from_bytes(recv_packet.target_ip, byteorder='big')),
                #       flush=True)
                if int.from_bytes(recv_packet.distance, byteorder='big') <= 1000:
                    # Lock tcp_links---------------------------------------------------------------------------#
                    lock.acquire()
                    possible_links = self.distance_table[
                        int.from_bytes(recv_packet.sourceIP, byteorder='big')].possible_switch
                    if int.from_bytes(recv_packet.target_ip, byteorder='big') in possible_links.keys():
                        if possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] >= int.from_bytes(
                                recv_packet.distance, byteorder='big'):
                            possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                                recv_packet.distance, byteorder='big')
                            # Broadcast distance
                            # print("check broadcast (link in)", flush=True)
                            self.broadcast(recv_packet,
                                           target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                            # Update shortest distance
                            # print("check update shortest(link in)", flush=True)
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                                 serve_socket)
                    else:
                        possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                            recv_packet.distance, byteorder='big')
                        # Broadcast distance
                        # print("check broadcast", flush=True)
                        self.broadcast(recv_packet, target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                        # Update shortest distance
                        # print("check update shortest", flush=True)
                        self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                             serve_socket)
                    # Release tcp_links-----------------------------------------------------------------------><
                    lock.release()
            elif recv_packet.real_mode == DATA:
                lock.acquire()
                # print("Data packet from server side source:" + bytes_to_ip(recv_packet.sourceIP) + " destination:" + bytes_to_ip(
                #     recv_packet.destinationIP) + " int dest: " + str(
                #     int.from_bytes(recv_packet.destinationIP, byteorder='big')), flush=True)
                port = serve_socket.getsockname()[1]
                if int.from_bytes(recv_packet.destinationIP, byteorder='big') not in self.shortest_distance_table.keys():
                    for link in self.clients_ips.keys():
                        if self.clients_ips[link].getsockname()[1] == port:
                            check_sum = int.from_bytes(recv_packet.sourceIP, byteorder='big') \
                                        + int.from_bytes(recv_packet.destinationIP, byteorder='big')
                            # print("special target ip:" + bytes_to_ip(recv_packet.sourceIP), flush=True)
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.sourceIP, byteorder='big'),
                                                 serve_socket, local_distance=check_sum, connect_switch_ip=link)
                self.data_process(recv_packet, data)
                lock.release()
            elif recv_packet.real_mode == AVAILABLE:
                # lock tcp_links----------------------------------------------------------------#
                lock.acquire()
                self.tcp_data[int.from_bytes(recv_packet.sourceIP, byteorder='big')].check_time = time.time()
                self.send_data_to_tcp(int.from_bytes(recv_packet.sourceIP, byteorder='big'))
                # Release tcp_links----------------------------------------------------------------<>
                lock.release()
            elif recv_packet.real_mode == QUERY:
                lock.acquire()
                available_packet = make_packet(bytes_to_ip(recv_packet.destinationIP),
                                               bytes_to_ip(recv_packet.sourceIP), 0x000000, AVAILABLE)
                serve_socket.sendall(available_packet)
                lock.release()

    def take_input(self):
        """
        Take command from stdin. Acceptable command is 'connect'
        """
        # time.sleep(0.5)
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                return
            else:
                self.connect_command(user_input)

    def connect_command(self, user_input):
        user_input_split = user_input.split(maxsplit=2)  # prevent splitting data
        if len(user_input_split) != 2:
            return
        command = user_input_split[0]
        port = user_input_split[1]
        try:
            port = int(port)
        except TypeError as e:
            return
        # Create packet and send
        if command in 'connect' and isinstance(port, int):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((LOCAL_HOST, port))
            discovery_packet = make_packet("0", "0", 0x000000, DISCOVERY, assigned_ip="0")
            client.send(discovery_packet)
            tcp_listen = threading.Thread(target=self.tcp_client_listening, args=(client,))
            tcp_listen.start()

    def tcp_client_listening(self, client=new_tcp_socket(0)):
        while True:
            data = client.recv(4096)
            recv_packet = GlobalPacket(data)
            if recv_packet.real_mode == OFFER:
                return_packet = make_packet("0", int_to_ip(int.from_bytes(recv_packet.sourceIP, byteorder='big')),
                                            0x000000, REQUEST,
                                            assigned_ip=int_to_ip(
                                                int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
                client.send(return_packet)

            elif recv_packet.real_mode == ACKNOWLEDGE:
                # Lock tcp_links--------------------------------------------------------------------------------------#
                lock.acquire()
                self.server_links[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = TCPLink(client,
                                                                                                   bytes_to_ip(
                                                                                                       recv_packet.assigned_ip),
                                                                                                   None)
                return_packet = make_packet(bytes_to_ip(recv_packet.assigned_ip),
                                            bytes_to_ip(recv_packet.sourceIP),
                                            0x000000,
                                            LOCATION,
                                            l_x=self.l_x,
                                            l_y=self.l_y)
                client.send(return_packet)
                # Release tcp_links--------------------------------------------------------------------------------<>
                lock.release()

            elif recv_packet.real_mode == LOCATION:
                # Lock tcp_links-----------------------#
                lock.acquire()
                int_source_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
                distance = calculate_distance(recv_packet.l_x, recv_packet.l_y, self.l_x, self.l_y)
                self.server_links[int_source_ip].distance = distance
                possible_link = {int_source_ip: distance}
                self.distance_table[int_source_ip] = PossibleDistance(client, possible_link)
                self.update_shortest(recv_packet, int_source_ip, client, local_distance=distance)
                # Broadcast distance
                # print("check broadcast", flush=True)
                self.broadcast(recv_packet, int_source_ip)
                # for link in self.tcp_links.keys():
                #     if link != int_source_ip and \
                #             link != int.from_bytes(recv_packet.destinationIP, byteorder='big'):
                #         tcp_client = self.tcp_links[link]
                #         # calculate the distance between neighbor and new link through self
                #         sum_distance = tcp_client.distance + self.distance_table[int_source_ip].possible_switch[int_source_ip]
                #         broadcast_packet = make_packet(link.client_ip, int_to_ip(link),
                #                                        0x000000, DISTANCE, target_ip=int_to_ip(link),
                #                                        distance=sum_distance)
                #         tcp_client.client.send(broadcast_packet)
                # Release tcp_links
                lock.release()

            elif recv_packet.real_mode == DISTANCE:
                # print("Distance packet received......" + str(
                #     int.from_bytes(recv_packet.distance, byteorder='big')) + ':' +
                #       str(int.from_bytes(recv_packet.target_ip, byteorder='big')),
                #       flush=True)
                if int.from_bytes(recv_packet.distance, byteorder='big') <= 1000:
                    # Lock tcp_links-----------------------------------------------------------------#
                    lock.acquire()
                    possible_links = self.distance_table[
                        int.from_bytes(recv_packet.sourceIP, byteorder='big')].possible_switch
                    if int.from_bytes(recv_packet.target_ip, byteorder='big') in possible_links.keys():
                        if possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] >= int.from_bytes(
                                recv_packet.distance, byteorder='big'):
                            possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                                recv_packet.distance, byteorder='big')
                            # Broadcast distance
                            self.broadcast(recv_packet,
                                           target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                            # Update shortest distance
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                                 client)
                    else:
                        possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                            recv_packet.distance, byteorder='big')
                        # Broadcast distance
                        self.broadcast(recv_packet, target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                        # Update shortest distance
                        self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                             client)
                    # Release tcp_links---------------------------------------------------------------<>
                    lock.release()
            elif recv_packet.real_mode == DATA:
                lock.acquire()
                port = client.getsockname()[1]
                # print("Data packet source:" + bytes_to_ip(recv_packet.sourceIP) + " destination:" + bytes_to_ip(
                #     recv_packet.destinationIP) + " int dest: " + str(
                #     int.from_bytes(recv_packet.destinationIP, byteorder='big')), flush=True)
                if int.from_bytes(recv_packet.destinationIP, byteorder='big') not in self.shortest_distance_table.keys():
                    for link in self.server_links.keys():
                        if self.server_links[link].client.getsockname()[1] == port:
                            check_sum = int.from_bytes(recv_packet.sourceIP, byteorder='big') \
                                        + int.from_bytes(recv_packet.destinationIP, byteorder='big')
                            # print("special target ip:" + str(int.from_bytes(recv_packet.sourceIP, byteorder='big')) + " ip:" + bytes_to_ip(recv_packet.sourceIP), flush=True)
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.sourceIP, byteorder='big'),
                                                 client, local_distance=check_sum, connect_switch_ip=link)
                self.data_process(recv_packet, data)
                lock.release()
            elif recv_packet.real_mode == AVAILABLE:
                # lock tcp_links----------------------------------------------------------------#
                lock.acquire()
                self.tcp_data[int.from_bytes(recv_packet.sourceIP, byteorder='big')].check_time = time.time()
                self.send_data_to_tcp(int.from_bytes(recv_packet.sourceIP, byteorder='big'))
                # Release tcp_links----------------------------------------------------------------<>
                lock.release()
            elif recv_packet.real_mode == QUERY:
                lock.acquire()
                available_packet = make_packet(bytes_to_ip(recv_packet.destinationIP),
                                               bytes_to_ip(recv_packet.sourceIP), 0x000000, AVAILABLE)
                client.sendall(available_packet)
                lock.release()

    def data_process(self, recv_packet, data):
        packet_list = [data]
        # If here is a record in the shortest path
        # print("Data packet source:" + bytes_to_ip(recv_packet.sourceIP) + " destination:" + bytes_to_ip(
        #     recv_packet.destinationIP) + " int dest: " + str(int.from_bytes(recv_packet.destinationIP, byteorder='big')), flush=True)
        # print(self.shortest_distance_table.keys(), flush=True)
        if int.from_bytes(recv_packet.destinationIP, byteorder='big') in self.shortest_distance_table.keys():
            # print("Data destination in shortest", flush=True)
            shortest_know_path = self.shortest_distance_table[
                int.from_bytes(recv_packet.destinationIP, byteorder='big')]
            if int.from_bytes(recv_packet.sourceIP, byteorder='big') + \
                    int.from_bytes(recv_packet.destinationIP, byteorder='big') == shortest_know_path[0].distance:
                tcp_link = shortest_know_path[0].connect_switch
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        self.send_tcp_query(tcp_link)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    self.send_tcp_query(tcp_link)

            elif len(shortest_know_path) == 1:
                tcp_link = shortest_know_path[0].connect_switch
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        self.send_tcp_query(tcp_link)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    self.send_tcp_query(tcp_link)

            elif len(shortest_know_path) == 2:
                ip_list = [shortest_know_path[0].connect_switch,
                           shortest_know_path[1].connect_switch]
                tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        self.send_tcp_query(tcp_link)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    self.send_tcp_query(tcp_link)
        # If No record in the shortest path
        else:
            # print("Data destination not in shortest", flush=True)
            ip_list = []
            for link in self.server_links.keys():
                ip_list.append(link)
            for link in self.clients_ips.keys():
                ip_list.append(link)
            tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
            # print("resend to:" + int_to_ip(tcp_link), flush=True)
            if tcp_link in self.tcp_data.keys():
                self.tcp_data[tcp_link].data.extend(packet_list)
                if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                    self.send_data_to_tcp(tcp_link)
                else:
                    self.send_tcp_query(tcp_link)
            else:
                self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                self.send_tcp_query(tcp_link)


class RUSHBSwitchGlobalLocal:
    def __init__(self, udp_serve_ip, tcp_serve_ip, udp_subnet, tcp_subnet, l_x, l_y):
        self.udp_serve_ip = udp_serve_ip
        self.tcp_serve_ip = tcp_serve_ip
        self.udp_subnet = udp_subnet
        self.tcp_subnet = tcp_subnet
        self.l_x = int(l_x)
        self.l_y = int(l_y)
        self.adapters = {}
        self.adapters_data = {}
        self.udp_socket = new_udp_socket(0)
        self.listen_socket = new_tcp_socket(0)
        self.listen_socket.listen(5)
        self.clients_ips = {}
        self.clients_distance = {}
        self.tcp_data = {}
        self.distance_table = {}
        self.shortest_distance_table = {}
        self.max_udp_ips = 2 ** (32 - int(self.udp_subnet)) - 2
        self.max_tcp_ips = 2 ** (32 - int(self.tcp_subnet)) - 2
        self.send_message = ''
        self.recv_message = ''

    def run(self):
        port = str(self.udp_socket.getsockname()[1])
        print(port, flush=True)
        tcp_port = str(self.listen_socket.getsockname()[1])
        print(tcp_port, flush=True)
        print("> ", end='', flush=True)
        udp = threading.Thread(target=self.listen_udp)
        udp.start()
        tcp_server = threading.Thread(target=self.receiving_tcp)
        tcp_server.start()

    def send_data_to_tcp(self, tcp_ip):
        send_socket = self.clients_ips[tcp_ip]
        for packet in self.tcp_data[tcp_ip].data:
            send_socket.sendall(packet)
        self.tcp_data[tcp_ip].data.clear()

    def send_data_to_udp(self, adapter_ip):
        adapter_data = self.adapters_data[adapter_ip]
        adapter_data.time = time.time()
        for data in adapter_data.data:
            self.udp_socket.sendto(data, self.adapters[adapter_ip])
        # clear adapter data
        adapter_data.data.clear()

    def send_query(self, adapter_ip):

        query_packet = make_packet(self.udp_serve_ip, adapter_ip, 0x000000, QUERY)
        self.udp_socket.sendto(query_packet, (LOCAL_HOST, self.adapters[adapter_ip]))

    def send_tcp_query(self, tcp_ip):

        query_packet = make_packet(self.tcp_serve_ip, int_to_ip(tcp_ip), 0x000000, QUERY)
        tcp_socket = self.clients_ips[tcp_ip]
        tcp_socket.sendall(query_packet)

    def listen_udp(self):
        while True:
            self.receiving_udp()

    def get_udp_ass_ip(self):
        if len(self.adapters) == 0:
            ip = ip_to_int(self.udp_serve_ip) + 1
        else:
            inverse = [(key, value) for key, value in self.adapters.items()]
            ip = max(inverse)[0] + 1
        return int_to_ip(ip)

    def get_tcp_ass_ip(self):
        if len(self.clients_ips) == 0:
            ip = ip_to_int(self.tcp_serve_ip) + 1
        else:
            inverse = [(key, value) for key, value in self.clients_ips.items()]
            # print("get assigned ip", flush=True)
            # print(inverse, flush=True)
            ip = max(inverse)[0] + 1
        return int_to_ip(ip)

    def broadcast(self, recv_packet, target_ip):
        # print("Neighbors:", flush=True)
        # print(self.clients_distance.keys(), flush=True)
        # print("Broadcast target_ip:" + str(target_ip), flush=True)
        int_source_ip = int.from_bytes(recv_packet.sourceIP, byteorder='big')
        for link in self.clients_distance.keys():
            if link != int_source_ip and \
                    link != int.from_bytes(recv_packet.destinationIP, byteorder='big') and \
                    link != target_ip:
                tcp_client = self.clients_distance[link]
                # calculate the distance between neighbor and new link through self
                sum_distance = tcp_client.distance + self.distance_table[int_source_ip].possible_switch[target_ip]
                broadcast_packet = make_packet(self.tcp_serve_ip, int_to_ip(link),
                                               0x000000, DISTANCE, target_ip=int_to_ip(target_ip),
                                               distance=sum_distance)
                # print("send broadcast packet for my client", flush=True)
                # print(tcp_client.client)
                tcp_client.client.sendall(broadcast_packet)

    def update_shortest(self, recv_packet, target_ip, client, local_distance=None):
        """
        recv_packet must be distance packet or location packet.
        """

        if local_distance is not None:
            new_distance = local_distance
            # print("New distance(typed) = " + str(new_distance), flush=True)
        else:
            new_distance = int.from_bytes(recv_packet.distance, byteorder='big')
            # print("New distance(from packet) = " + str(new_distance), flush=True)
        if target_ip in self.shortest_distance_table.keys():
            for distance in self.shortest_distance_table[target_ip]:
                if new_distance < distance.distance:
                    self.shortest_distance_table[target_ip] = [Distance(client,
                                                                        int.from_bytes(recv_packet.sourceIP,
                                                                                       byteorder='big'),
                                                                        new_distance)]
                    # print("replace shortest table for " + str(target_ip), flush=True)
                    break
                elif new_distance == distance.distance:
                    self.shortest_distance_table[target_ip].append(Distance(client, int.from_bytes(recv_packet.sourceIP,
                                                                                                   byteorder='big'),
                                                                            new_distance))
                    # print("update same distance shortest table for " + str(target_ip), flush=True)
                    break
        else:
            self.shortest_distance_table[target_ip] = [Distance(client, int.from_bytes(recv_packet.sourceIP,
                                                                                       byteorder='big'), new_distance)]
            # print("update a new record in shortest table for " + str(target_ip), flush=True)

    def receiving_udp(self):
        data, address = self.udp_socket.recvfrom(RECV_SIZE)
        recv_packet = LocalPacket(data)
        # sys.stdout.write("Receive:" + "\n")
        # sys.stdout.flush()
        lock.acquire()
        # print(data)
        lock.release()
        if recv_packet.real_mode == DISCOVERY:
            if len(self.adapters) == self.max_udp_ips:  # If the subnet amount has been run out, ignore new adapter connect.
                return
            return_packet = make_packet(self.udp_serve_ip, "0", 0x000000, OFFER, assigned_ip=self.get_udp_ass_ip())
            self.udp_socket.sendto(return_packet, address)
        elif recv_packet.real_mode == REQUEST:
            return_packet = make_packet(self.udp_serve_ip,
                                        int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')),
                                        0x000000,
                                        ACKNOWLEDGE,
                                        assigned_ip=int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
            self.udp_socket.sendto(return_packet, address)
            # Add a new adapter connection in dictionary
            self.adapters[ip_to_int(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))] = address[1]
            # print("Add one new adapter: " + str(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big'))))
        # elif recv_packet.real_mode == AVAILABLE:

    def receiving_tcp(self):
        while True:
            new_socket, address = self.listen_socket.accept()
            tcp_server = threading.Thread(target=self.tcp_server, args=(new_socket,))
            tcp_server.start()

    def tcp_server(self, serve_socket=new_tcp_socket(0)):
        while True:
            data = serve_socket.recv(4096)
            recv_packet = GlobalPacket(data)
            # lock.acquire()
            # print(recv_packet.real_mode)
            # lock.release()
            if recv_packet.real_mode == DISCOVERY:
                if len(self.clients_ips) == self.max_tcp_ips:  # If the subnet amount has been run out, ignore new adapter connect.
                    return
                return_packet = make_packet(self.tcp_serve_ip, "0", 0x000000, OFFER, assigned_ip=self.get_tcp_ass_ip())
                serve_socket.sendall(return_packet)

            elif recv_packet.real_mode == REQUEST:
                # Lock tcp_links-----------------------------------------------------------------#
                lock.acquire()
                return_packet = make_packet(self.tcp_serve_ip,
                                            int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')),
                                            0x000000,
                                            ACKNOWLEDGE,
                                            assigned_ip=int_to_ip(
                                                int.from_bytes(recv_packet.assigned_ip, byteorder='big')))
                serve_socket.sendall(return_packet)
                # Add a new adapter connection in dictionary
                self.clients_ips[
                    ip_to_int(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big')))] = serve_socket
                # print("Add one new client: " + str(int_to_ip(int.from_bytes(recv_packet.assigned_ip, byteorder='big'))),
                #       flush=True)
                # Release tcp link--------------------------------------------------------------------------<>
                lock.release()

            elif recv_packet.real_mode == LOCATION:
                # Lock tcp_links--------------------------------------------------------------------#
                lock.acquire()
                distance = calculate_distance(self.l_x, self.l_y, recv_packet.l_x, recv_packet.l_y)
                self.clients_distance[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = Distance(serve_socket,
                                                                                                        int.from_bytes(
                                                                                                            recv_packet.sourceIP,
                                                                                                            byteorder='big'),
                                                                                                        distance)
                # print("New switch distance: " + str(distance), flush=True)
                possible_link = {int.from_bytes(recv_packet.sourceIP, byteorder='big'): distance}
                self.distance_table[int.from_bytes(recv_packet.sourceIP, byteorder='big')] = PossibleDistance(
                    serve_socket, possible_link)
                self.update_shortest(recv_packet, int.from_bytes(recv_packet.sourceIP, byteorder='big'), serve_socket,
                                     local_distance=distance)
                return_packet = make_packet(self.tcp_serve_ip, bytes_to_ip(recv_packet.sourceIP), 0x000000, LOCATION,
                                            l_x=self.l_x,
                                            l_y=self.l_y)
                serve_socket.sendall(return_packet)
                # Send udp distance to new neighbor
                return_udp_ip_packet = make_packet(self.tcp_serve_ip, bytes_to_ip(recv_packet.sourceIP), 0x000000,
                                                   DISTANCE,
                                                   target_ip=self.udp_serve_ip,
                                                   distance=distance)
                # print("Send udp ip to new neighbor : " + str(ip_to_int(self.udp_serve_ip)), flush=True)
                serve_socket.sendall(return_udp_ip_packet)
                # Release tcp link----------------------------------------------------------------------<>
                lock.release()

            elif recv_packet.real_mode == DISTANCE:
                lock.acquire()
                # print("Distance packet received......" + str(
                #     int.from_bytes(recv_packet.distance, byteorder='big')) + ':' +
                #       str(int.from_bytes(recv_packet.target_ip, byteorder='big')) + " From:" +
                #       str(int.from_bytes(recv_packet.sourceIP, byteorder='big')),
                #       flush=True)
                if int.from_bytes(recv_packet.distance, byteorder='big') <= 1000:
                    # Lock tcp_links---------------------------------------------------------------------------#

                    possible_links = self.distance_table[
                        int.from_bytes(recv_packet.sourceIP, byteorder='big')].possible_switch
                    if int.from_bytes(recv_packet.target_ip, byteorder='big') in possible_links.keys():
                        if possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] >= int.from_bytes(
                                recv_packet.distance, byteorder='big'):
                            possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                                recv_packet.distance, byteorder='big')
                            # Broadcast distance
                            # print("check broadcast (link in)", flush=True)
                            self.broadcast(recv_packet,
                                           target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                            # Update shortest distance
                            # print("check update shortest(link in)", flush=True)
                            self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                                 serve_socket)
                    else:
                        possible_links[int.from_bytes(recv_packet.target_ip, byteorder='big')] = int.from_bytes(
                            recv_packet.distance, byteorder='big')
                        # Broadcast distance
                        # print("check broadcast", flush=True)
                        self.broadcast(recv_packet, target_ip=int.from_bytes(recv_packet.target_ip, byteorder='big'))
                        # Update shortest distance
                        # print("check update shortest", flush=True)
                        self.update_shortest(recv_packet, int.from_bytes(recv_packet.target_ip, byteorder='big'),
                                             serve_socket)
                    # Release tcp_links-----------------------------------------------------------------------><
                lock.release()
            elif recv_packet.real_mode == DATA:
                lock.acquire()
                self.data_process(recv_packet, data)
                lock.release()
            elif recv_packet.real_mode == AVAILABLE:
                lock.acquire()
                self.tcp_data[int.from_bytes(recv_packet.sourceIP, byteorder='big')].check_time = time.time()
                self.send_data_to_tcp(int.from_bytes(recv_packet.sourceIP, byteorder='big'))
                lock.release()
            elif recv_packet.real_mode == QUERY:
                lock.acquire()
                available_packet = make_packet(bytes_to_ip(recv_packet.destinationIP),
                                               bytes_to_ip(recv_packet.sourceIP), 0x000000, AVAILABLE)
                serve_socket.sendall(available_packet)
                lock.release()

    def data_process(self, recv_packet, data):
        packet_list = [data]
        # If here is a record in the shortest path
        if int.from_bytes(recv_packet.destinationIP, byteorder='big') in self.shortest_distance_table.keys():
            shortest_know_path = self.shortest_distance_table[
                int.from_bytes(recv_packet.destinationIP, byteorder='big')]

            if len(shortest_know_path) == 1:
                tcp_link = shortest_know_path[0].connect_switch
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        self.send_tcp_query(tcp_link)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    self.send_tcp_query(tcp_link)

            elif len(shortest_know_path) == 2:
                ip_list = [shortest_know_path[0].connect_switch,
                           shortest_know_path[1].connect_switch]
                tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
                if tcp_link in self.tcp_data.keys():
                    self.tcp_data[tcp_link].data.extend(packet_list)
                    if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                        self.send_data_to_tcp(tcp_link)
                    else:
                        self.send_tcp_query(tcp_link)
                else:
                    self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                    self.send_tcp_query(tcp_link)
        # If No record in the shortest path
        else:
            ip_list = []
            for link in self.clients_ips.keys():
                ip_list.append(link)
            tcp_link = fetch_prefix(int.from_bytes(recv_packet.sourceIP, byteorder='big'), ip_list)
            if tcp_link in self.tcp_data.keys():
                self.tcp_data[tcp_link].data.extend(packet_list)
                if time.time() - self.tcp_data[tcp_link].check_time <= 5:
                    self.send_data_to_tcp(tcp_link)
                else:
                    self.send_tcp_query(tcp_link)
            else:
                self.tcp_data[tcp_link] = Data(time.time(), packet_list)
                self.send_tcp_query(tcp_link)


class TCPLink:
    def __init__(self, client, client_ip, distance):
        self.client = client
        self.client_ip = client_ip
        self.distance = distance


class Distance:
    def __init__(self, client, connect_switch_ip, distance):
        self.client = client
        self.connect_switch = connect_switch_ip
        self.distance = distance


class PossibleDistance:
    def __init__(self, client, possible_switch):
        self.client = client
        self.possible_switch = possible_switch


class LocalPacket:
    def __init__(self, data):
        # All field are bytes.
        self.sourceIP = data[0:4]
        self.destinationIP = data[4:8]
        self.offset = data[8:11]
        self.mode = data[11:12]
        self.real_mode = int.from_bytes(self.mode, byteorder='big')
        if self.real_mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            self.assigned_ip = data[12:16]
        elif self.real_mode == DATA:
            self.data = data[12:]


class GlobalPacket:
    def __init__(self, data):
        # All field are bytes.
        self.sourceIP = data[0:4]
        self.destinationIP = data[4:8]
        self.offset = data[8:11]
        self.mode = data[11:12]
        self.real_mode = int.from_bytes(self.mode, byteorder='big')
        if self.real_mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            self.assigned_ip = data[12:16]
        elif self.real_mode == DATA:
            self.data = data[12:]
        elif self.real_mode == LOCATION:
            self.l_x = int.from_bytes(data[12:14], byteorder='big')
            self.l_y = int.from_bytes(data[14:16], byteorder='big')
        elif self.real_mode == DISTANCE:
            self.target_ip = data[12:16]
            self.distance = data[16:20]


class Data:
    def __init__(self, check_time, data=None, ):
        if data is None:
            data = []
        self.data = data
        self.check_time = check_time


def main(argv):
    if len(argv) < 6:
        if argv[1] == "local":
            my_serve = (argv[2]).split("/", 1)[0]
            my_subnet = (argv[2]).split("/", 1)[1]
            local_x = argv[3]
            local_y = argv[4]
            t1 = threading.Thread(target=RUSHBSwitchLocal(my_serve, my_subnet, local_x, local_y).run)
            t1.start()
        if argv[1] == 'global':
            global_serve = (argv[2]).split("/", 1)[0]
            global_subnet = (argv[2]).split("/", 1)[1]
            global_x = argv[3]
            global_y = argv[4]
            RUSHBSwitchGlobal(global_serve, global_subnet, global_x, global_y).run()
    if len(argv) == 6:
        my_serve = (argv[2]).split("/", 1)[0]
        my_subnet = (argv[2]).split("/", 1)[1]
        global_serve = (argv[3]).split("/", 1)[0]
        global_subnet = (argv[3]).split("/", 1)[1]
        global_x = argv[4]
        global_y = argv[5]
        t1 = threading.Thread(target=RUSHBSwitchGlobalLocal(my_serve, global_serve, my_subnet, global_subnet, global_x,
                                                            global_y).run)
        t1.start()


if __name__ == '__main__':
    main(sys.argv)
