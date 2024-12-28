from CovertChannelBase import CovertChannelBase

import json
import time
import random

import scapy.all as scapy
import scapy.layers
import scapy.layers.l2
import scapy.layers.inet
import scapy.sendrecv
import scapy.packet
from scapy.all import sniff, IP, ICMP
from scapy.packet import Packet


class MyCovertChannel(CovertChannelBase):
    """
    MyCovertChannel class implements a covert storage channel using protocol field manipulation.
    - Encodes and decodes binary messages in IP header fields (TOS).
    - Handles sending and receiving packets using Scapy.
    """

    def __init__(self):
        """
        Initializes any required variables for encoding/decoding messages.
        """
        pass

    def generate_rand_hex(self, possible_values) -> str:
        """
        Selects a random value from a given list of possible values.
        Args:
            possible_values: List of valid hex values for encoding.
        Returns:
            A randomly selected hex value.
        """
        selected_hex = possible_values[random.randint(0, len(possible_values)-1)]
        return selected_hex

    def encode_message(self, two_bits: str, possible_values, xor_res_to_bits):
        """
        Encodes 2 bits into an 8-bit TOS value.
        Args:
            two_bits: 2-bit binary string to encode.
            possible_values: List of valid starting patterns.
            xor_res_to_bits: Mapping for XOR results to bit pairs.
        Returns:
            Encoded binary string.
        """
        selected_hex = self.generate_rand_hex(possible_values)
        a = selected_hex
        zero_second_digit = None
        one_second_digit = None

        for i in a:
            if i == "0":
                if zero_second_digit is None:
                    xx = xor_res_to_bits[two_bits[0]][random.randint(0, 1)]
                    selected_hex += xx[0]
                    zero_second_digit = xx[1]
                else:
                    selected_hex += zero_second_digit
            else:
                if one_second_digit is None:
                    xx = xor_res_to_bits[two_bits[1]][random.randint(0, 1)]
                    selected_hex += xx[0]
                    one_second_digit = xx[1]
                else:
                    selected_hex += one_second_digit

        return selected_hex

    def decode_message(self, total_hash):
        """
        Decodes a binary string extracted from TOS values.
        Args:
            total_hash: Concatenated binary string to decode.
        Returns:
            Decoded 2-bit binary string.
        """
        decoded_hex = ""

        zero_first_digit = None
        one_first_digit = None

        zero_xor = None
        one_xor = None

        half_len = int(len(total_hash)/2)
        assert half_len == 4

        for i in range(half_len):
            pattern_bit = total_hash[i]
            corresponding_bit = total_hash[i + half_len]
            if pattern_bit == "0":
                if zero_first_digit is None:
                    zero_first_digit = corresponding_bit
                else:
                    zero_xor = int(zero_first_digit) ^ int(corresponding_bit)
            else:
                if one_first_digit is None:
                    one_first_digit = corresponding_bit
                else:
                    one_xor = int(one_first_digit) ^ int(corresponding_bit)
        
        return str(zero_xor) + str(one_xor)

    def send(self, log_file_name, possible_values, xor_res_to_bits, send_sleep_time_in_ms,
             sender_decoded_bit_length, receiver_ip):
        """
        Sends covert messages by encoding binary data into TOS fields of IP packets.
        Args:
            log_file_name: File name for logging the sent message.
            possible_values: Valid binary patterns for encoding.
            xor_res_to_bits: XOR mapping for encoding.
            send_sleep_time_in_ms: Delay between packet transmissions.
            sender_decoded_bit_length: Bits encoded per packet.
            receiver_ip: Receiver's IP address.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for index in range(0, len(binary_message), sender_decoded_bit_length):
            tos_ = self.encode_message(binary_message[index:index+sender_decoded_bit_length], 
                                       possible_values, xor_res_to_bits)
            tos_dec = int(tos_, 2)
            ip_packet = scapy.layers.inet.IP(dst=receiver_ip, tos=tos_dec)
            icmp_request = scapy.layers.inet.ICMP()
            packet = ip_packet / icmp_request
            super().send(packet)
            time.sleep(send_sleep_time_in_ms / 1000)

    def receive(self, log_file_name,
                received_decoded_bit_length, received_encoded_bit_length,
                sender_ip):
        """
        Receives covert messages by decoding binary data from TOS fields of IP packets.
        Args:
            log_file_name: File name for logging the received message.
            received_decoded_bit_length: Bits decoded per packet.
            received_encoded_bit_length: Expected encoded bits per packet.
            sender_ip: Sender's IP address.
        """
        self.log_message("", log_file_name)
        decoded_part = ""
        res = ""

        while True:
            packet = sniff(filter="icmp", count=1)[0]
            if scapy.layers.inet.IP in packet and scapy.layers.inet.ICMP in packet:
                b = packet.json()
                tos_ = json.loads(b)["payload"]["tos"]
                decodd = str(bin(tos_)[received_decoded_bit_length:])
                if len(decodd) < received_encoded_bit_length:
                    decodd = "0" * (received_encoded_bit_length - len(decodd)) + decodd
                decoded_binary = self.decode_message(decodd)
                decoded_part += decoded_binary
                if len(decoded_part) % 8 == 0:
                    obtained_char = self.convert_eight_bits_to_character(decoded_part)
                    decoded_part = ""
                    res += obtained_char
                    if obtained_char == ".":
                        break
        self.log_message(res, log_file_name)
