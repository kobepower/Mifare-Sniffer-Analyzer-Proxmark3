# Mifare-Sniffer-Analyzer-Proxmark3
MIFARE Trace Parser
A simple MATLAB script to parse Proxmark3 trace files for MIFARE cards. Extracts UIDs, keys, PRNG status, and read block data.
Features

Detects and lists unique UIDs and keys from the trace.
Identifies PRNG (Pseudo-Random Number Generator) status.
Parses read block commands and their decrypted data.
Provides a summary of extracted information.

Requirements

MATLAB (tested on R2020a and later).

Usage

Run the function in MATLAB:
matlabparseMifareTrace('path/to/your/tracefile.txt');

If no filename is provided, it prompts for one via file dialog or command line.


The script will output the analysis to the console, including found UIDs, keys, block data, and a summary.

Example Output
text=== MIFARE TRACE ANALYSIS ===

Found UID: XXXXXXXX
Found Key: XXXXXXXXXXXXXXXX
PRNG Status: prng success
Block 0 Data: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX

=== SUMMARY ===
Total UIDs found: 1
Total Keys found: 1
Total Blocks read: 1
Limitations

Assumes standard Proxmark3 trace format.
Only handles basic MIFARE commands (UID, key auth, read blocks).

License
MIT License. Feel free to use and modify.
