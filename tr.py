import ipaddress
import struct
import pe
from m import UdpTrackerConnection, UdpTrackerAnnounce, UdpTrackerAnnounceOutput
from pem import PeersManager

import requests
import logging
from bcoding import bdecode
import socket
from urllib.parse import urlparse

# Constants to control the number of peer connections.
MAX_PEERS_TRY_CONNECT = 30  # Maximum number of attempted connections to peers from trackers.
MAX_PEERS_CONNECTED = 8     # Maximum number of successfully connected peers.

# Class to represent a socket address (IP and port).
class SockAddr:
    def __init__(self, ip, port, allowed=True):
        self.ip = ip        # IP address of the socket.
        self.port = port    # Port number of the socket.
        self.allowed = allowed  # A flag to indicate if this socket is allowed.

    def __hash__(self):
        return "%s:%d" % (self.ip, self.port)

# The Tracker class handles tracker communication and peer connections.
class Tracker(object):
    def __init__(self, torrent):
        self.torrent = torrent  # Torrent object containing information about the torrent file.
        self.threads_list = []  # List to store threads for peer connections (not used in the provided code).
        self.connected_peers = {}  # Dictionary to store connected peers with their hash as the key.
        self.dict_sock_addr = {}   # Dictionary to store socket addresses of potential peers.

    # Get peers from all trackers associated with the torrent.
    def get_peers_from_trackers(self):
        for i, tracker in enumerate(self.torrent.announce_list):
            if len(self.dict_sock_addr) >= MAX_PEERS_TRY_CONNECT:
                break  # Stop trying to connect to more peers if the maximum limit is reached.

            tracker_url = tracker[0]  # Extract the tracker URL from the announce list.

            if str.startswith(tracker_url, "http"):
                try:
                    self.http_scraper(self.torrent, tracker_url)  # Scrape peers from HTTP tracker.
                except Exception as e:
                    logging.error("HTTP scraping failed: %s " % e.__str__())

            elif str.startswith(tracker_url, "udp"):
                try:
                    self.udp_scrapper(tracker_url)  # Scrape peers from UDP tracker.
                except Exception as e:
                    logging.error("UDP scraping failed: %s " % e.__str__())

            else:
                logging.error("unknown scheme for: %s " % tracker_url)

        self.try_peer_connect()  # Attempt to connect to the discovered peers.

        return self.connected_peers  # Return the connected peers dictionary.

    # Try to establish connections to the discovered peers.
    def try_peer_connect(self):
        logging.info("Trying to connect to %d peer(s)" % len(self.dict_sock_addr))

        for _, sock_addr in self.dict_sock_addr.items():
            if len(self.connected_peers) >= MAX_PEERS_CONNECTED:
                break  # Stop trying to connect more peers if the maximum limit is reached.

            # Create a new Peer object to represent the peer to be connected.
            new_peer = pe.Peer(int(self.torrent.number_of_pieces), sock_addr.ip, sock_addr.port)

            if not new_peer.connect():
                continue  # If connection fails, skip to the next potential peer.

            print('Connected to %d/%d peers' % (len(self.connected_peers), MAX_PEERS_CONNECTED))

            self.connected_peers[new_peer.__hash__()] = new_peer  # Add the connected peer to the dictionary.

    # Scrape peers from an HTTP tracker.
    def http_scraper(self, torrent, tracker):
        params = {
            'info_hash': torrent.info_hash,
            'peer_id': torrent.peer_id,
            'uploaded': 0,
            'downloaded': 0,
            'port': 6881,
            'left': torrent.total_length,
            'event': 'started'
        }

        try:
            answer_tracker = requests.get(tracker, params=params, timeout=5)  # Send GET request to the tracker.
            list_peers = bdecode(answer_tracker.content)  # Decode the response using bencoding.

            offset = 0
            if not type(list_peers['peers']) == list:
                '''
                    - Handles bytes form of list of peers
                    - IP address in bytes form:
                        - Size of each IP: 6 bytes
                        - The first 4 bytes are for IP address
                        - Next 2 bytes are for port number
                    - To unpack initial 4 bytes !i (big-endian, 4 bytes) is used.
                    - To unpack next 2 bytes !H(big-endian, 2 bytes) is used.
                '''
                for _ in range(len(list_peers['peers'])//6):
                    ip = struct.unpack_from("!i", list_peers['peers'], offset)[0]
                    ip = socket.inet_ntoa(struct.pack("!i", ip))
                    offset += 4
                    port = struct.unpack_from("!H", list_peers['peers'], offset)[0]
                    offset += 2
                    s = SockAddr(ip, port)
                    self.dict_sock_addr[s.__hash__()] = s
            else:
                for p in list_peers['peers']:
                    s = SockAddr(p['ip'], p['port'])
                    self.dict_sock_addr[s.__hash__()] = s

        except Exception as e:
            logging.exception("HTTP scraping failed: %s" % e.__str__())

    # Scrape peers from a UDP tracker.
    def udp_scrapper(self, announce):
        torrent = self.torrent
        parsed = urlparse(announce)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(4)
        ip, port = socket.gethostbyname(parsed.hostname), parsed.port

        if ipaddress.ip_address(ip).is_private:
            return  # Skip private IP addresses.

        tracker_connection_input = UdpTrackerConnection()
        response = self.send_message((ip, port), sock, tracker_connection_input)  # Send connection request to tracker.

        if not response:
            raise Exception("No response for UdpTrackerConnection")

        tracker_connection_output = UdpTrackerConnection()
        tracker_connection_output.from_bytes(response)  # Parse the response from the tracker.

        tracker_announce_input = UdpTrackerAnnounce(torrent.info_hash, tracker_connection_output.conn_id,
                                                    torrent.peer_id)
        response = self.send_message((ip, port), sock, tracker_announce_input)  # Send announce request to tracker.

        if not response:
            raise Exception("No response for UdpTrackerAnnounce")

        tracker_announce_output = UdpTrackerAnnounceOutput()
        tracker_announce_output.from_bytes(response)  # Parse the response from the tracker.

        for ip, port in tracker_announce_output.list_sock_addr:
            sock_addr = SockAddr(ip, port)

            if sock_addr.__hash__() not in self.dict_sock_addr:
                self.dict_sock_addr[sock_addr.__hash__()] = sock_addr

        print("Got %d peers" % len(self.dict_sock_addr))

    # Send a message to the tracker and receive the response.
    def send_message(self, conn, sock, tracker_message):
        message = tracker_message.to_bytes()
        trans_id = tracker_message.trans_id
        action = tracker_message.action
        size = len(message)

        sock.sendto(message, conn)  # Send the message to the tracker.

        try:
            response = PeersManager._read_from_socket(sock)  # Read the response from the socket.
        except socket.timeout as e:
            logging.debug("Timeout : %s" % e)
            return
        except Exception as e:
            logging.exception("Unexpected error when sending message : %s" % e.__str__())
            return

        if len(response) < size:
            logging.debug("Did not get full message.")

        if action != response[0:4] or trans_id != response[4:8]:
            logging.debug("Transaction or Action ID did not match")

        return response
