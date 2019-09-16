# Rem-Cap

Demonstrating gRPC client-streaming API for my blog by implementing a packet sniffer in which the client streams it's network packets to a remote gRPC server.

## WIP

Todo :

 - Fix bugs
   - panicing on close of network interface channels
   - pcap from previous session is generated on next session start (clear/reset server buffer on crash?)

- Add flag cli flag to configure host gRPC server

- Add unit-tests for client and server and test for race-conditions, memory-leaks, 
  and proper closing of resources etc...

- Add Dockerfile and Makefile
    

