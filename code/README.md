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
1. Generate an 8-bit encoded TOS value.
2. Match bits based on the pattern and XOR them to encode '10'.
3. Send this encoded value within the TOS field of an IP packet.

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
