import time
import socket
import struct
import bitstring
from pubsub import pub
import logging
import m

class Peer(object):
    def __init__(self, number_of_pieces, ip, port=6881):
        # Initialize the Peer object with its attributes
        self.last_call = 0.0
        self.has_handshaked = False
        self.healthy = False
        self.read_buffer = b''  # Buffer to store received data
        self.socket = None  # Socket object for communication
        self.ip = ip  # IP address of the peer
        self.port = port  # Port number of the peer
        self.number_of_pieces = number_of_pieces  # Total number of pieces in the torrent
        self.bit_field = bitstring.BitArray(number_of_pieces)  # Bit field representing the pieces
        self.state = {
            'am_choking': True,
            'am_interested': False,
            'peer_choking': True,
            'peer_interested': False,
        }
        # Initial state of the peer, including choking and interest flags

    def __hash__(self):
        return "%s:%d" % (self.ip, self.port)
        # Returns a unique hash for the Peer object based on its IP address and port

    def connect(self):
        try:
            self.socket = socket.create_connection((self.ip, self.port), timeout=2)
            self.socket.setblocking(False)
            logging.debug("Connected to peer ip: {} - port: {}".format(self.ip, self.port))
            self.healthy = True
            # Attempt to create a socket connection with the peer and set it to non-blocking mode
            # Set the 'healthy' flag to True if connection is successful

        except Exception as e:
            print("Failed to connect to peer (ip: %s - port: %s - %s)" % (self.ip, self.port, e.__str__()))
            return False
            # If connection fails, print an error message and return False

        return True
        # Return True if the connection is successfully established

    def send_to_peer(self, msg):
        try:
            self.socket.send(msg)
            self.last_call = time.time()
            # Send the provided message to the peer over the socket connection
            # Update the last_call attribute with the current time

        except Exception as e:
            self.healthy = False
            logging.error("Failed to send to peer : %s" % e.__str__())
            # If sending fails, set the 'healthy' flag to False and log an error message

    def is_eligible(self):
        now = time.time()
        return (now - self.last_call) > 0.2
        # Check if the time elapsed since the last call is greater than 0.2 seconds
        # Return True if eligible, False otherwise

    def has_piece(self, index):
        return self.bit_field[index]
        # Check if the peer has the piece at the given index in its bit field
        # Return True if the peer has the piece, False otherwise

    def am_choking(self):
        return self.state['am_choking']
        # Check if the peer is choking (not sending data to the client)
        # Return True if the peer is choking, False otherwise

    def am_unchoking(self):
        return not self.am_choking()
        # Check if the peer is unchoking (sending data to the client)
        # Return True if the peer is unchoking, False otherwise

    def is_choking(self):
        return self.state['peer_choking']
        # Check if the peer is being choked by the client (client not sending requests)
        # Return True if the peer is being choked, False otherwise

    def is_unchoked(self):
        return not self.is_choking()
        # Check if the peer is unchoked by the client (client sending requests)
        # Return True if the peer is unchoked, False otherwise

    def is_interested(self):
        return self.state['peer_interested']
        # Check if the peer is interested in the client's pieces
        # Return True if the peer is interested, False otherwise

    def am_interested(self):
        return self.state['am_interested']
        # Check if the client is interested in the peer's pieces
        # Return True if the client is interested, False otherwise

    def handle_choke(self):
        logging.debug('handle_choke - %s' % self.ip)
        self.state['peer_choking'] = True
        # Handle the choke message from the peer
        # Set the 'peer_choking' flag to True

    def handle_unchoke(self):
        logging.debug('handle_unchoke - %s' % self.ip)
        self.state['peer_choking'] = False
        # Handle the unchoke message from the peer
        # Set the 'peer_choking' flag to False

    def handle_interested(self):
        logging.debug('handle_interested - %s' % self.ip)
        self.state['peer_interested'] = True
        # Handle the interested message from the peer
        # Set the 'peer_interested' flag to True

        if self.am_choking():
            unchoke = message.UnChoke().to_bytes()
            self.send_to_peer(unchoke)
            # If the client is choking, send an unchoke message to the peer

    def handle_not_interested(self):
        logging.debug('handle_not_interested - %s' % self.ip)
        self.state['peer_interested'] = False
        # Handle the not interested message from the peer
        # Set the 'peer_interested' flag to False

    def handle_have(self, have):
        """
        :type have: message.Have
        """
        logging.debug('handle_have - ip: %s - piece: %s' % (self.ip, have.piece_index))
        self.bit_field[have.piece_index] = True
        # Handle the have message from the peer
        # Set the bit at the piece index in the bit field to True

        if self.is_choking() and not self.state['am_interested']:
            interested = message.Interested().to_bytes()
            self.send_to_peer(interested)
            self.state['am_interested'] = True
            # If the client is choking and not interested, send an interested message to the peer
            # Set the 'am_interested' flag to True

    def handle_bitfield(self, bitfield):
        """
        :type bitfield: message.BitField
        """
        logging.debug('handle_bitfield - %s - %s' % (self.ip, bitfield.bitfield))
        self.bit_field = bitfield.bitfield
        # Handle the bitfield message from the peer
        # Update the bit field of the peer with the received bit field

        if self.is_choking() and not self.state['am_interested']:
            interested = m.Interested().to_bytes()
            self.send_to_peer(interested)
            self.state['am_interested'] = True
            # If the client is choking and not interested, send an interested message to the peer
            # Set the 'am_interested' flag to True

    def handle_request(self, request):
        """
        :type request: message.Request
        """
        logging.debug('handle_request - %s' % self.ip)
        if self.is_interested() and self.is_unchoked():
            pub.sendMessage('PiecesManager.PeerRequestsPiece', request=request, peer=self)
            # Handle the request message from the peer
            # If the client is interested and unchoked, publish the message for the PiecesManager to handle

    def handle_piece(self, message):
        """
        :type message: message.Piece
        """
        pub.sendMessage('PiecesManager.Piece', piece=(message.piece_index, message.block_offset, message.block))
        # Handle the piece message from the peer
        # Publish the message for the PiecesManager to handle

    def handle_cancel(self):
        logging.debug('handle_cancel - %s' % self.ip)
        # Handle the cancel message from the peer

    def handle_port_request(self):
        logging.debug('handle_port_request - %s' % self.ip)
        # Handle the port request message from the peer

    def _handle_handshake(self):
        try:
            handshake_message = m.Handshake.from_bytes(self.read_buffer)
            self.has_handshaked = True
            self.read_buffer = self.read_buffer[handshake_message.total_length:]
            logging.debug('handle_handshake - %s' % self.ip)
            return True
            # Handle the handshake message from the peer
            # Set the 'has_handshaked' flag to True and update the read buffer

        except Exception:
            logging.exception("First message should always be a handshake message")
            self.healthy = False
            # If an exception occurs while handling the handshake message, set the 'healthy' flag to False

        return False
        # Return False if the handshake message handling fails

    def _handle_keep_alive(self):
        # Handle the keep-alive message from the peer
        try:
            keep_alive = m.KeepAlive.from_bytes(self.read_buffer)
            logging.debug('handle_keep_alive - %s' % self.ip)
        except m.WrongMessageException:
            return False
        except Exception:
            logging.exception("Error KeepALive, (need at least 4 bytes : {})".format(len(self.read_buffer)))
            return False
        # Update the read buffer and return True if keep-alive message handling is successful    
        self.read_buffer = self.read_buffer[keep_alive.total_length:]
        return True                

    def get_messages(self):
        # Continuously loop while there is data in the read buffer and the peer is healthy
        # Handle handshake and keep-alive messages and continue to the next iteration if successful
        while len(self.read_buffer) > 4 and self.healthy:
            if (not self.has_handshaked and self._handle_handshake()) or self._handle_keep_alive():
                continue

            payload_length, = struct.unpack(">I", self.read_buffer[:4])
            total_length = payload_length + 4

            if len(self.read_buffer) < total_length:
                break
            else:
                # Extract the payload from the read buffer based on the payload length
                payload = self.read_buffer[:total_length]
                self.read_buffer = self.read_buffer[total_length:]

            try:
                # Dispatch the received message using the MessageDispatcher class
                # If a valid message is received, yield it for further processing
                received_message = m.MessageDispatcher(payload).dispatch()
                if received_message:
                    yield received_message
            except m.WrongMessageException as e:
                # If an exception occurs while dispatching the message, set the 'healthy' flag to False and break the loop
                logging.exception(e.__str__())        

    #def __str__(self):
     #   return "Peer {}:{}".format(self.ip, self.port)
        # Return a string representation of the Peer object
