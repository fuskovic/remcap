# With SSL/TLS secured connection

### Building

The make target provided named `remcap` automates the following :

- Generating the certificates, keys, and the CSR.
- Self-signing the certificate.
- Building the server and client executables.

The `remcap` make target requires two args that are needed for generating certs and keys:

- host (which is the openssl subject common name)
- pw (which is the passphrase)

``Example`` :

    make remcap host=$(hostname) pw=go4it

## Running the Server

Example that toggles enabling of TLS to true and runs the server on port 80 :

    ./remcap_server --enable-tls --cert=ssl/server.crt --key=ssl/server.pem -p 80


## Running the Client

`Requirements for running on a remote target`

- `scp` the `ca.crt` file to the remote target
- `scp` the `remcap` executable to the remote target.
- Shell into the target
- Escalate priviledges ( root is required for sniffing )

Example that toggles enabling of TLS to true and will sniff the network interface device named en0 for 1 hour and 30 minutes. 

The host value should be the same value you passed the `host` arg when you ran the `make remcap` target.

The client streams any sniffed packets to the host.

    ./remcap --enable-tls --cert ca.crt --host <host>:80 --hours 1 -m 30 -d en0
