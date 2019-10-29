# Remcap 

Remotely capture network packets using a client-streaming gRPC API.

## Table of Contents

### Usage
- [Server](#server)
- [Client](#client)

### Ways to Use

- [With an SSL/TLS secured connection](https://github.com/fuskovic/remcap/blob/master/docs/secure.md)
- [Insecure connection](https://github.com/fuskovic/remcap/blob/master/docs/insecure.md)
- [Docker](https://github.com/fuskovic/remcap/blob/master/docs/docker.md)

## How it works

The server binary runs on your machine and is responsible for receiving packets and outputting pcaps.

The client binary runs on the remote target specifying :

- which network interfaces to sniff
- the amount of time to sniff
- the address and port of the gRPC server to stream sniffed packets to
- the path to the trust certificate

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


## Usage


<a name="server"></a>
### Server

    Usage:
    remcap [flags]

    Flags:
        --cert          string        Path to signed certificate
        --enable-tls    bool          Secure connection with SSL/TLS
    -h, --help                        help for remcap
        --key           string        Path to server private key
    -o, --out           string        Specify out file name
    -p, --port          string        Port to start remcap server


<a name="client"></a>
### Client

    Usage:
    remcap [flags] [command]

    Available Commands:
    bpf         Apply Berkely Packet Filters
    help        Help about any command

    Flags:
        --cert          string      Path to trust certificate
    -d, --devices       strings     Network interfaces to sniff (comma-separated )
        --enable-tls    bool        Secure connection with SSL/TLS
    -h, --help                      Help for remcap
        --host          string      <ip>:<port> of host to stream packets to
        --hours         int         Amount of hours to run capture
    -m, --minutes       int         Amount of minutes to run capture
    -s, --seconds       int         Amount of seconds to run capture
