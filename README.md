## A rusty cousin to [Drill](https://github.com/NLnetLabs/ldns).

Use by cloning the repo and `cargo build`, and using the `bore` executable as you would any other.

Note that currently the query is sent to `127.0.0.1:53` by default. This can be changed with the command line flags.

The supported flags are:
```
    -h, --help               Print help information
    -p, --port <port>        The port of the server that is query is sent to
    -q, --qtype <qtype>      The query type of the request
    -s, --server <server>    The server that is query is sent to
    -V, --version            Print version information
    --do                     Set the DO bit to request DNSSEC records
    --nsid                   Request the nsid
```
