import wan_optimizer
from tcp_packet import Packet
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'
    WINDOW_SIZE = 48

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.flows_to_buffers = {} # Maps flows (src, dest) pairs to buffers
        # Maps flows (src, dest) pairs to pointer to first byte of window
        # we'll compute the next hash over.
        self.buffer_pointers = {}
        self.caches = {}
        # self.flows_to_caches = {} # Maps flows to a dictionary of seen values for that flow
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        flow = (packet.src, packet.dest)
        if not self.is_open_flow(flow):
            self.reset_buffer(flow)
        # if flow not in self.flows_to_caches:
        #     self.flows_to_caches[flow] = {}

        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            self.receive_client(packet)
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.receive_source(packet)

    def reset_buffer(self, flow):
        self.flows_to_buffers[flow] = ""
        self.buffer_pointers[flow] = 0

    def is_open_flow(self, flow):
        return flow in self.flows_to_buffers

    def receive_client(self, packet):
        outgoing_port = self.address_to_port[packet.dest]
        flow = (packet.src, packet.dest)
        if packet.is_raw_data:
            # send data through
            self.send(packet, outgoing_port)
            self.receive_helper(packet, self.flush_buffer_client)
        else: # it's a hash
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            hashed = packet.payload
            unhashed = cache[hashed]
            # construct new packet from unhashed data, send it
            self.packetize_and_send(unhashed, flow, packet.is_fin, outgoing_port)
        if packet.is_fin:
            self.handle_flow_fin_client(flow)

    def receive_helper(self, packet, flush_buffer):
        # Takes care of all the common buffer handling code
        # flush_buffer should be a function that takes a packet as an argument
        flow = (packet.src, packet.dest)
        # cache = self.flows_to_caches[flow]
        cache = self.caches
        # Read payload
        packet_length = packet.size()
        for i in range(packet_length):
            self.flows_to_buffers[flow] += packet.payload[i]
            hashed = self.compute_hash(flow)
            if hashed is not None:
                if self.is_block_end(hashed):
                    flush_buffer(flow)
                else:
                    self.buffer_pointers[flow] += 1

    def is_long_enough(self, block):
        return (len(block) >= self.WINDOW_SIZE)

    def is_block_end(self, hashed):
        to_compare = utils.get_last_n_bits(hashed, len(self.GLOBAL_MATCH_BITSTRING))
        return (to_compare == self.GLOBAL_MATCH_BITSTRING)

    def flush_buffer_client(self, flow):
        curr_buffer = self.flows_to_buffers[flow]
        hashed = utils.get_hash(curr_buffer)
        if hashed is not None:
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            curr_buffer = self.flows_to_buffers[flow]
            cache[hashed] = curr_buffer
        self.reset_buffer(flow)

    def handle_flow_fin_client(self, flow):
        # Caches whatever is leftover in the buffer. Then closes the flow.
        curr_buffer = self.flows_to_buffers[flow]
        hashed = utils.get_hash(curr_buffer)
        if hashed is not None:
            curr_buffer = self.flows_to_buffers[flow]
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            cache[hashed] = curr_buffer
        self.close_flow(flow)

    def receive_source(self, packet):
        self.receive_helper(packet,self.flush_buffer_source)
        if packet.is_fin:
            flow = (packet.src, packet.dest)
            self.handle_flow_fin_source(flow)


    def flush_buffer_source(self, flow):
        curr_buffer = self.flows_to_buffers[flow]
        hashed = utils.get_hash(curr_buffer)
        # cache = self.flows_to_caches[flow]
        cache = self.caches
        # Can assume not handling fin packet
        if (hashed is not None) and (hashed in cache): # send hashed block
            src, dest = flow
            hash_packet = Packet(src,dest, False, False, hashed)
            self.send(hash_packet, self.wan_port)
        else: # hash and send data
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            curr_buffer = self.flows_to_buffers[flow]
            if hashed is not None:
                cache[hashed] = curr_buffer
            self.packetize_and_send(curr_buffer, flow, False, self.wan_port)
        self.reset_buffer(flow)

    def compute_hash(self,flow):
        # Returns hash for a flow. Returns None if not enough data to hash.
        curr_buffer = self.flows_to_buffers[flow]
        curr_ptr = self.buffer_pointers[flow]
        hashed = None
        if self.is_long_enough(curr_buffer):
            to_hash = curr_buffer[curr_ptr:curr_ptr + self.WINDOW_SIZE]
            hashed = utils.get_hash(to_hash)
        return hashed

    def handle_flow_fin_source(self, flow):
        # Hashes and sends whatever is left in the buffer
        # and does flow cleanup
        curr_buffer = self.flows_to_buffers[flow]
        hashed = utils.get_hash(curr_buffer)
        # cache = self.flows_to_caches[flow]
        cache = self.caches
        if (hashed is not None) and (hashed in cache):
            src, dest = flow[0], flow[1]
            hash_packet = Packet(src, dest, False, True, hashed) # is_fin = True
            self.send(hash_packet, self.wan_port)
        else:
            curr_buffer = self.flows_to_buffers[flow]
            if hashed is not None:
                cache[hashed] = curr_buffer
            self.packetize_and_send(curr_buffer, flow, True, self.wan_port)
        self.close_flow(flow)

    def close_flow(self, flow):
        del self.flows_to_buffers[flow]
        del self.buffer_pointers[flow]

    def packetize_and_send(self, to_send, flow, is_fin, outgoing_port):
        """Packetizes and sends everything in to_send"""
        src, dest = flow[0], flow[1]
        num_full_packets = len(to_send) / utils.MAX_PACKET_SIZE
        for i in range(num_full_packets):
            subset = to_send[i*utils.MAX_PACKET_SIZE:(i+1)*utils.MAX_PACKET_SIZE]
            new_packet = Packet(src, dest, True, False, subset)
            self.send(new_packet, outgoing_port)
        # leftovers - note will send an empty packet on purpose if nothing left
        subset = to_send[num_full_packets*utils.MAX_PACKET_SIZE:]
        tail_packet = Packet(src, dest, True, is_fin, subset)
        self.send(tail_packet, outgoing_port)
