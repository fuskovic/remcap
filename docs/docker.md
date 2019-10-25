
# Docker

## Building and Running the Server

I've provided a make target that automates the following :

- Stand up a containerized remcap server
- Host-to-container port mapping of 80:80
- Build the client binary

Example :

    make ready

## Running the Client

`Requirements for running on a remote target`

- `scp` the `ca.crt` file to the remote target
- `scp` the `remcap` executable to the remote target.
- Shell into the target
- Escalate priviledges ( root is required for sniffing )

Example:

Sniffs the network interface device named en0 for 1 hour and 30 minutes. 

We can use the IP address of the container or the server
that spun it up since we mapped ports.


    ./remcap --host <ip>:<port> --hours 1 -m 30 -d en0

The client will stream any sniffed packets to the containerized remcap server.

`Note` : The container is ephemeral and any pcap files it it saves will be destroyed lost when the container is stopped. 

With that said, you should shell into the container after you believe any remote packet capture sessions you started may have completed. 

Any pcaps you scored will have been saved to `server/pcaps/`.

I also provided a make target for getting a container shell.

    make interactive
