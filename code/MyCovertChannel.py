from CovertChannelBase import CovertChannelBase

import time
import json
import random
import struct
import socket

import scapy.all as scapy
import scapy.layers
import scapy.layers.l2
import scapy.layers.inet
import scapy.sendrecv
import scapy.packet
from scapy.all import sniff, IP, ICMP


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        # self.possible_values = [
        #     "0011",  # 3
        #     "0101",  # 5
        #     "0110",  # 6
        #     "1001",  # 9
        #     "1010",  # 10
        #     "1100",  # 12
        # ]
        # self.xor_res_to_bits = {
        #     "0": [["0", "0"], ["1", "1"]],
        #     "1": [["1", "0"], ["0", "1"]]
        # }
    
    def generate_rand_hex(self, possible_values) -> str:
        selected_hex = possible_values[random.randint(0, len(possible_values)-1)]
        return selected_hex

    def encode_message(self, two_bits: str, possible_values, xor_res_to_bits):
        """two_bits in ilk bit i 0 larin tuttuklarinin xor u olucak"""
        selected_hex = self.generate_rand_hex(possible_values)
        a = selected_hex
        zero_second_digit = None
        one_second_digit = None
        for i in a:
            if i == "0":
                if zero_second_digit is None:
                    xx = xor_res_to_bits[two_bits[0]][random.randint(0,1)]
                    selected_hex += xx[0]
                    zero_second_digit = xx[1]
                else:
                    selected_hex += zero_second_digit
            else:  # i == "1"
                if one_second_digit is None:
                    xx = xor_res_to_bits[two_bits[1]][random.randint(0,1)]
                    selected_hex += xx[0]
                    one_second_digit = xx[1]
                else:
                    selected_hex += one_second_digit
        print("two_bits:", two_bits, "\tselected_hex:", selected_hex)
        return selected_hex

    def decode_message(self, total_hash):
        # print("total_hash:", total_hash)
        decoded_hex = ""

        zero_first_digit = None
        one_first_digit = None

        zero_xor = None
        one_xor = None

        for i in range(4):
            first_ = total_hash[i]
            second_ = total_hash[i+4]
            if first_ == "0":
                if zero_first_digit is None:
                    zero_first_digit = second_
                else:
                    zero_xor = int(zero_first_digit) ^ int(second_)
            else:  # i == "1"
                if one_first_digit is None:
                    one_first_digit = second_
                else:
                    one_xor = int(one_first_digit) ^ int(second_)
        
        return str(zero_xor) + str(one_xor)

    # def create_ip_packet(self, tos):
    #     version = 4  # IPv4
    #     ihl = 5      # Header length
    #     tot_len = 20 # Total length (no payload)
    #     id = 54321   # Identification
    #     frag_off = 0 # Fragment offset
    #     ttl = 64     # Time-to-live
    #     protocol = 6 # TCP
    #     src_ip = "192.168.1.1"  # Source IP
    #     dst_ip = "192.168.1.2"  # Destination IP

    #     # Create the IP header
    #     ver_ihl = (version << 4) + ihl
    #     header = scapy.packet.Packet('!BBHHHBBH4s4s',
    #                         ver_ihl, tos, tot_len, id, frag_off,
    #                         ttl, protocol, 0,  # Checksum is 0 for now
    #                         socket.inet_aton(src_ip),
    #                         socket.inet_aton(dst_ip))

    #     return header

    def send(self, log_file_name, parameter1, parameter2, 
             possible_values, xor_res_to_bits, send_sleep_time_in_ms,
             receiver_ip):  # parameter2 is the number of 0's in first 4 bits
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        bps_calc_message = self.generate_random_binary_message(16,16)

        binary_message = bps_calc_message

        print(f"binary_message ({type(binary_message)}) :", binary_message)
        print([self.convert_eight_bits_to_character(binary_message[x:x+8]) for x in range(0, len(binary_message), 8)])

        start_time = time.time()
        for index in range(0, len(binary_message), 2):

            tos_ = self.encode_message(binary_message[index:index+2], possible_values, xor_res_to_bits)
            print(tos_, end="\t")
            tos_dec = int(tos_, 2)

            ip_packet = scapy.layers.inet.IP(dst=receiver_ip, tos=tos_dec)

            icmp_request = scapy.layers.inet.ICMP()
            packet = ip_packet / icmp_request

            super().send(packet, interface="eth0")

            # scapy.sendrecv.send(packet)

            time.sleep(send_sleep_time_in_ms/1000)
        end_time = time.time()

        print("TIME CONSUMED:", 128/(end_time - start_time))


    def receive(self, parameter1, parameter2, parameter3, log_file_name,
                received_decoded_bit_length, received_encoded_bit_length,
                sender_ip):
        """
        - This function listens for ICMP packets in a continuous loop to extract covert data.
        - It filters packets based on ICMP type and processes them to decode hidden information.
        - Logs each packet's details to a specified log file.
        """

        self.log_message("", log_file_name)
        decoded_part = ""
        count = 0

        res = ""

        while True:
            # Capture a single packet with ICMP filter
            packet = sniff(filter="icmp", count=1)[0]
            count += received_decoded_bit_length

            if scapy.layers.inet.IP in packet and scapy.layers.inet.ICMP in packet:

                # Display packet details
                # print(packet)
                # print("***************")
                
                # Convert packet to JSON format and extract 'tos'
                b = packet.json()
                tos_ = json.loads(b)["payload"]["tos"]

                decodd = str(bin(tos_)[received_decoded_bit_length:])
                if len(decodd) < received_encoded_bit_length:
                    decodd = "0"*(received_encoded_bit_length-len(decodd)) + decodd
                print(decodd)
                
                decoded_binary = self.decode_message(decodd)
                decoded_part += decoded_binary

                if len(decoded_part) % 8 == 0:
                    obtained_char = self.convert_eight_bits_to_character(decoded_part)
                    decoded_part = ""

                    # print(obtained_char, end="")
                    
                    res += obtained_char

                    if obtained_char == ".":
                        break
        print()
        # Log the packet data
        self.log_message(res, log_file_name)

