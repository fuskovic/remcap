# Rem-Cap 

Remotely capture network packets using a client-streaming gRPC API.

## How it works

The server runs on your box and is responsible for receiving packets and outputting pcaps.

The client binary and trust certificate need to be `scp`'d onto the target machine.

Run the binary and specify :

- which network interfaces to sniff
- the amount of time to sniff
- the address and port of the gRPC server to stream sniffed packets to
- the path to the trust certificate you scp'd over

The server keeps track of which packets came from which client stream.

Server-side logging shows :

- The connection status of any clients.
- The number of packets received from any connections.

Client-side logging shows : 

- How much time has elapsed out of the total session time specified
- The number of packets captured from all interfaces so far

All logs update in real-time.

When a client's session is over, the connection is closed and a session summary is printed to stdout.

On the server-side, the server writes all captured packets of a closed connection to disk in the form of a pcap and will be found in `server/pcaps/` .

The pcap file can then be analyzed in wireshark or some other pcap analyzing tool.

## Compiling

`pre-reqs` :  Download [Go](https://golang.org/)

clone this repo

Install dependencies : 

    go get ./...

The creation of certificates, keys, and both remcap binaries ( server and client ) can be automated with the `remcap` target in the Makefile.

The make target requires pw and host args for key and cert generation

``Example`` :

    make remcap pw=test host=localhost

All generated certificates and keys will be saved into a new `ssl/` dir.

## Server Usage

    Usage:

    remcap [flags]

    Flags:
        --cert          string        Path to signed certificate
    -h, --help                        help for remcap
        --key           string        Path to server private key
    -o, --out           string        Specify out file name
    -p, --port          string        Port to start remcap server


## Running Server

    ./remcap_server --cert=ssl/server.crt --key=ssl/server.pem -p 4444

## Client Usage

    Usage:
    remcap [flags] [command]

    Available Commands:
    bpf         Apply Berkely Packet Filters
    help        Help about any command

    Flags:
        --cert      string      Path to trust certificate
    -d, --devices   strings     Network interfaces to sniff ( comma-separated )
    -h, --help                  Help for remcap
        --host      string      <ip>:<port> of host to stream packets to
        --hours     int         Amount of hours to run capture
    -m, --minutes   int         Amount of minutes to run capture
    -s, --seconds   int         Amount of seconds to run capture

## Running client :

`What a localhost test would look like` :

        ./remcap -s 10 -d en0 --host localhost:4444 --cert ssl/ca.crt 

The above example would sniff the en0 interface for 10 seconds and stream any packets captured to the server running on localhost:4444. The cert is used for the three-way handshake to secure the connection.

`Requirements for executing on a remote target` :

- Root
- `scp` the client binary ( `remcap` ) and the `ca.crt` file over

And run the command again, passing the ip and port the gRPC server is running on

        ./remcap -s 10 -d en0 --host <ip>:<port> --cert /path/to/ca.crt 
