import wan_optimizer
from tcp_packet import Packet
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.flows_to_buffers = {} # Maps flows (src, dest) pairs to buffers
        self.flows_to_caches = {} # Maps flows to a dictionary of seen values for that flow
        self.caches = {}
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        flow = (packet.src, packet.dest)
        if not self.is_open_flow(flow):
            self.flows_to_buffers[flow] = ""
        # if flow not in self.flows_to_caches:
        #     self.flows_to_caches[flow] = {}
        # cache = self.flows_to_caches[flow]
        cache = self.caches

        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            outgoing_port = self.address_to_port[packet.dest]
            if packet.is_raw_data :
                # send data through
                self.send(packet, outgoing_port)
                self.buffer_and_cache(packet)
            else: # it's a hash
                hashed = packet.payload
                unhashed = cache[hashed]
                # construct new packet from unhashed data, send it
                self.packetize_and_send(unhashed,flow, packet.is_fin, outgoing_port)

            if packet.is_fin:
                self.flush_buffer(flow) # finish caching whatever's in the buffer
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.buffer_cache_and_send(packet)
            if packet.is_fin:
                self.send_remaining_in_buffer(flow)
                self.delete_buffer(flow)

    def is_open_flow(self, flow):
        return flow in self.flows_to_buffers

    def buffer_and_cache(self, packet):
        # Adds packet to buffer, and caches the hash if buffer is full
        flow = (packet.src, packet.dest)
        curr_buffer = self.flows_to_buffers[flow]
        buffer_size = len(curr_buffer)
        remaining_bytes = self.BLOCK_SIZE - buffer_size
        if packet.size() < remaining_bytes:
            self.flows_to_buffers[flow] = curr_buffer + packet.payload
        else:
            to_hash = curr_buffer + packet.payload[:remaining_bytes]
            hashed = utils.get_hash(to_hash)
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            cache[hashed] = to_hash
            self.flows_to_buffers[flow] = packet.payload[remaining_bytes:]

    def flush_buffer(self, flow):
        # Caches whatever is leftover in the buffer. Then deletes buffer.
        # Used when FIN packet is seen.
        curr_buffer = self.flows_to_buffers[flow]
        # cache = self.flows_to_caches[flow]
        cache = self.caches
        if (len(curr_buffer) > 0):
            hashed = utils.get_hash(curr_buffer)
            cache[hashed] = curr_buffer
        self.delete_buffer(flow)

    def delete_buffer(self,flow):
        del self.flows_to_buffers[flow]

    def buffer_cache_and_send(self, packet):
        flow = (packet.src, packet.dest)
        curr_buffer = self.flows_to_buffers[flow]
        buffer_size = len(curr_buffer)
        remaining_bytes = self.BLOCK_SIZE - buffer_size
        if packet.size() < remaining_bytes:
            self.flows_to_buffers[flow] = curr_buffer + packet.payload
        else: # buffer full
            to_hash = curr_buffer + packet.payload[:remaining_bytes]
            hashed = utils.get_hash(to_hash)
            # cache = self.flows_to_caches[flow]
            cache = self.caches
            # All FIN packets sent by send_remaining_in_buffer
            if hashed in cache: # send hashed block
                hash_packet =  Packet(packet.src, packet.dest, False, False, hashed)
                self.send(hash_packet, self.wan_port)
            else: # hash and send data
                cache[hashed] = to_hash
                self.packetize_and_send(to_hash,flow, False, self.wan_port)
            self.flows_to_buffers[flow] = packet.payload[remaining_bytes:]

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

    def send_remaining_in_buffer(self, flow):
        # Hash and sends whatever is left in the buffer
        curr_buffer = self.flows_to_buffers[flow]
        hashed = utils.get_hash(curr_buffer)
        src, dest = flow[0], flow[1]
        # cache = self.flows_to_caches[flow]
        cache = self.caches
        if hashed in cache: # send hashed
            hash_packet =  Packet(src, dest, False, True, hashed) # is_fin = True
            self.send(hash_packet, self.wan_port)
        else: # hash and send raw data
            cache[hashed] = curr_buffer
            self.packetize_and_send(curr_buffer, flow, True, self.wan_port)
