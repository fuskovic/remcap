# With an Insecure Connection

## Building

The remcap target provided named `binaries` automates building the client and server executables.

    make binaries

## Running the Server

Example that runs the server on port 80:

    ./remcap_server -p 80

## Running the Client

Example that sniffs the network interface device named en0 for 5 minutes and streams any captured packets to our server's ip and port it's running on.

    ./remcap --host <ip>:80 -m 5 -d en0
