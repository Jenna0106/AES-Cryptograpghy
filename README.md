# AES-Cryptograpghy
AES encryption and decryption implemented on Basys-3 FPGA Board

# AES Encryption and Decryption with 7-Segment Display  
**Verilog Implementation on FPGA (Basys 3 Compatible)**

## Description

This project implements AES-128 encryption and decryption in Verilog and visualizes the data using a 4-digit 7-segment display. A hardcoded 128-bit plaintext is encrypted and decrypted using a fixed key, with the data displayed segment-by-segment on the FPGA board.

The project is ideal for learning AES internals and digital system integration using Verilog HDL.

---

## Features

- AES-128 Encryption and Decryption  
- Hardcoded plaintext and key  
- Displays data on 7-segment displays in hexadecimal (grouped in 4 digits)  
- Scrolls through 8 groups (128 bits = 32 hex digits)  
- Accepts switch-based trigger input for encryption and decryption  
- Compatible with Basys 3 FPGA board  

---

## Functional Overview

| Mode | Description |
|------|-------------|
| 00 | Shows hardcoded plaintext |
| 01 | Displays AES encrypted ciphertext |
| 10 | Displays decrypted plaintext |

Each mode scrolls through the 128-bit data 16 bits (4 hex digits) at a time, pausing for 2 seconds between transitions. A dash line appears briefly between complete cycles.

---

## Inputs and Outputs

### Inputs

| Signal         | Description                   |
|----------------|-------------------------------|
| `clk`          | 100 MHz system clock          |
| `reset_n`      | Active-low reset button       |
| `start_encrypt`| Start encryption (switch)     |
| `start_decrypt`| Start decryption (switch)     |

### Outputs

| Signal     | Description                              |
|------------|------------------------------------------|
| `seg[6:0]` | 7-segment display segments (active-low)  |
| `an[3:0]`  | 7-segment display anode control (active-low) |

---

## Setup Instructions

1. Open **Vivado** and create a new RTL project.
2. Add all `.v` Verilog source files.
3. Add the `constraints.xdc` file (ensure it matches Basys 3 pin mapping).
4. Synthesize, implement, and generate the bitstream.
5. Upload the bitstream to your FPGA board.
6. Use the slider switches to initiate encryption and decryption.

---

## Technical Details

- **AES Key**: `128'h000102030405060708090a0b0c0d0e0f`  
- **Plaintext**: `128'h00112233445566778899aabbccddeeff`  
- **Encryption rounds**: 10 (AES-128 standard)  
- **Encryption triggers when**: `start_encrypt` is high  
- **Decryption triggers when**: `start_decrypt` is high  

---

## Future Improvements

- Allow dynamic input of plaintext/key through UART or switches  
- Add LED indicators for mode status  
- Extend support to AES-192 or AES-256  
- Add testbenches and simulation waveforms for validation  

---

## License

This project is open-source and intended for **educational and academic use only**.  
No warranties or guarantees are provided.

