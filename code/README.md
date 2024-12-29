# Covert Storage Channel that exploits Protocol Field Manipulation using Type of Service field in IP

## Overview
This project implements a **Covert Storage Channel** that exploits the **Type of Service (TOS)** field in the IP header for data transfer. The covert channel leverages unused bits in the TOS field to encode and transmit hidden messages between two endpoints.

The implementation includes:
1. **Message Encoding and Decoding:** The message is encoded using a custom bit manipulation scheme within the TOS field and decoded by the receiver.
2. **Packet Transmission and Reception:** Messages are sent and received using ICMP packets.
3. **Logging and Testing Framework:** The system logs sent and received messages for verification.

## Encoding Scheme
- Each 8-bit TOS field encodes **2 bits** of actual message data.
- The first 4 bits determine the encoding pattern, containing **two 0s and two 1s**.
- The XOR operation between pairs of bits determines the encoded message bits.
- The XOR operation of the **0 bits pattern** gives first bit, **1 bits pattern** gives the second bit.
- The encoded bits are extracted and reconstructed into characters by the receiver.

### Encoding Example
For a binary message '10':
1. **Input:** Binary bits to encode = '10'.
2. **Step 1:** Generate a random 4-bit pattern (e.g., '0101') satisfying two 0s and two 1s.
3. **Step 2:** Map the input '10' into the remaining 4 bits by XOR logic:
   - First bit ('1'): Use XOR mapping '1 → [1, 0] or [0, 1]' → We can select '10' to add corresponding area.
      - Like: '0101 1_0_' the XOR result of this 1 and zero gives us first bit which is 1.
   - Second bit ('0'): Use XOR mapping '0 → [0, 0] or [1, 1]' → We can select '00' to add corresponding area.
      - The final version becomes '0101 1000'.
4. **Output:** Encoded 8-bit value = '01011000'.
5. **Transmission:** This value is sent in the TOS field of an IP packet.

### Decoding Example
1. **Input:** Received 8-bit TOS value = '01011000'.
2. **Step 1:** Split the first 4 bits ('0101') and last 4 bits ('1000').
3. **Step 2:** Perform XOR to decode:
   - First pair in the last 4 bits (where the 0 values in the first 4 bits) contains '1' and '0' bits: XOR result → '1'.
   - Second pair in the last 4 bits (where the 1 values in the first 4 bits) contains '0' and '0' bits: XOR → '0'.
4. **Output:** Decoded bits = '10'.
5. **Character Mapping:** Combine decoded bits into characters to reconstruct the original message.

## Implementation Details
### Key Components
- **MyCovertChannel.py**: Contains the main logic for encoding, decoding, sending, and receiving messages.
- **CovertChannelBase.py**: Provides utility functions for binary conversion, logging, and sending packets.
- **run.py**: Script to execute send and receive operations.
- **config.json**: Configuration file to set parameters like IP addresses, encoding patterns, and logs.
- **Makefile**: Automation script for running tests and verifying logs.

### Measurement of Covert Channel Capacity
The covert channel capacity is calculated based on the time taken to send and receive messages.

**Capacity Formula:**
```
Capacity (bps) = Total Bits Sent / Transmission Time (seconds)
```
In our implementation:
- Total bits sent = 128 bits.
- Transmission time = ~8.01 seconds.
- **Measured Capacity: 15.98 bits per second**.

## How to Run the Code
1. **Sender:**
   ```bash
   make send
   ```
2. **Receiver:**
   ```bash
   make receive
   ```
3. **Compare Logs:**
   ```bash
   make compare
   ```
4. **View Documentation:**
   ```bash
   make documentation
   ```

## Results
- **Logs Comparison:** Logs generated at sender and receiver are compared to ensure message integrity.
- **Capacity Measurement:** Covert channel capacity achieved: **15.98 bps**.

## Limitations
- The implementation relies on the TOS field, which may be overwritten or stripped by network devices.
- The capacity may vary based on network latency and system performance.

## Conclusion
This project successfully demonstrates a covert storage channel exploiting the TOS field in IP headers. It achieves a capacity of approximately **15.98 bits per second** and provides a framework for further exploration of covert channels in networking protocols.
