use std::{fmt, io, process};
use std::net::{UdpSocket, IpAddr, SocketAddr};
use clap::{Command, Parser};
use domain::base::{
        Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget,
        iana::OptionCode, octets::OctetsBuilder, message::Message,
        opt::AllOptData
};
use domain::rdata::AllRecordData;
use domain::resolv::stub::conf::ResolvConf;


#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[command(author = "Tom Carpay, NLnet Labs")]
#[command(version = "0.1")]
#[command(about = "A Rusty cousin to drill", long_about = None)]
struct GlobalParamArgs {
    /// The query name that is going to be resolved
    #[arg(value_name="QUERY_NAME")]
    qname: Dname<Vec<u8>>,

    /// The query type of the request
    #[arg(long, default_value = "A")]
    qtype: Rtype,

    /// The server that is query is sent to
    #[arg(short = 's', long, value_name="IP_ADDRESS")]
    server: Option<IpAddr>,

    /// The port of the server that is query is sent to
    #[arg(short = 'p', long = "port", value_parser = clap::value_parser!(u16))]
    port: Option<u16>,

    /// Set the DO bit to request DNSSEC records
    #[arg(long = "do")]
    do_bit: bool,

    /// Request the server NSID
    #[arg(long = "nsid")]
    nsid: bool,
}

#[derive(Clone, Debug)]
struct Request {
    args: GlobalParamArgs,
    upstream: SocketAddr,
}

impl Request {
    fn configure(args: GlobalParamArgs) -> Result<Self, String> {
        let mut upstreams = ResolvConf::default();

        let upstream: SocketAddr = match (args.server, args.port) {
            (Some(addr), Some(port)) => SocketAddr::new(addr, port),
            (Some(addr), None) => SocketAddr::new(addr, 0),
            (None, Some(port)) => {
                upstreams.servers[0].addr.set_port(port);
                upstreams.servers[0].addr
            },
            (None, None) => upstreams.servers[0].addr,
        };

        // @TODO choose between v4 and v6 for upstream

        Ok(Request {
            args: args.clone(), // @TODO find better way?
            upstream,
        })
    }

    fn process(self) -> Result<(), BoreError> {
        // Bind a UDP socket to a kernel-provided port
        let socket = match self.upstream {
            SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address"),
            SocketAddr::V6(_) => UdpSocket::bind("[::]:0").expect("couldn't bind to address"),
        };

        let message = self.create_message()?;

        // Send message off to the server using our socket
        // @TODO this is a temp solution
        socket.send_to(&message.as_dgram_slice(), self.upstream)?;

        // Create recv buffer
        let mut buffer = vec![0; 1232];

        // Recv in buffer
        socket.recv_from(&mut buffer)?;

        // Parse the response
        let response = Message::from_octets(buffer).map_err(|_| "bad response")?;
        self.print_response(response);

        /* Print message information */
        println!(";; SERVER: {}", self.upstream);

        Ok(())
    }


    fn create_message(&self) -> Result<StreamTarget<Vec<u8>>, BoreError> {
        // @TODO create the sections individually to gain more control/flexibility

        // Create a message builder wrapping a compressor wrapping a stream
        // target.
        let mut msg = MessageBuilder::from_target(
            StaticCompressor::new(
                    StreamTarget::new_vec()
            )
        ).unwrap();

        // Set the RD bit and a random ID in the header and proceed to
        // the question section.
        msg.header_mut().set_rd(true);
        msg.header_mut().set_random_id();
        let mut msg = msg.question();

        // Add a question and proceed to the answer section.
        msg.push((&self.args.qname, self.args.qtype)).unwrap();

        let mut msg = msg.additional();

        // Add an OPT record.
        // @TODO make this configurable
        msg.opt(|opt| {
            opt.set_udp_payload_size(4096);

            if self.args.nsid {
                opt.push_raw_option(OptionCode::Nsid, |target| {
                    target.append_slice(b" ")
                })?;
            }

            if self.args.do_bit {
                opt.set_dnssec_ok(true);
            }

            Ok(())
        }).unwrap();

        // Convert the builder into the actual message.
        Ok(msg.finish().into_target())
    }

    fn print_response(&self, response: Message<Vec<u8>>) {
        /* Header */
        let header = response.header();

        println!(";; ->>HEADER<<- opcode: {}, rcode: {}, id: {}",
                header.opcode(), header.rcode(), header.id());

        print!(";; flags: {}", header.flags());

        let count = response.header_counts();
        println!(" ; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
            count.qdcount(), count.ancount(), count.nscount(), count.arcount());

        /* Question */
        println!(";; QUESTION SECTION:");

        let question_section = response.question();

        for question in question_section {
            println!(";; {}", question.unwrap());
        }

        /* Answer */
        println!("\n;; ANSWER SECTION:");

        /* Unpack and parse with all known record types */
        let answer_section = response.answer().unwrap().limit_to::<AllRecordData<_, _>>();

        for record in answer_section {
            println!(";; {}", record.unwrap());
        }

        /* Authority */
        println!("\n;; AUTHORITY SECTION:");

        let authority_section = response.authority().unwrap().limit_to::<AllRecordData<_, _>>();

        for record in authority_section {
            println!("{}", record.unwrap());
        }

        /* Additional */
        println!("\n;; ADDITIONAL SECTION:");

        let opt_record = response.opt().unwrap();

        println!(";; EDNS: version {}; flags: {}; udp: {}", // @TODO remove hardcode UDP
            opt_record.version(), opt_record.dnssec_ok(), opt_record.udp_payload_size()); 


        for option in opt_record.iter::<AllOptData<_>>() {
            let opt = option.unwrap();
            match opt {
                AllOptData::Nsid(nsid) => println!("; NSID: {}", nsid),
                AllOptData::Dau(dau) => println!("; DAU: {}", dau),
                AllOptData::Dhu(dhu) => println!("; DHU: {}", dhu),
                AllOptData::N3u(n3u) => println!("; N3U: {}", n3u),
                AllOptData::Expire(expire) => println!("; EXPIRE: {}", expire),
                AllOptData::TcpKeepalive(tcpkeepalive) => println!("; TCPKEEPALIVE: {}", tcpkeepalive),
                AllOptData::Padding(padding) => println!("; PADDING: {}", padding),
                AllOptData::ClientSubnet(clientsubnet) => println!("; CLIENTSUBNET: {}", clientsubnet),
                AllOptData::Cookie(cookie) => println!("; COOKIE: {}", cookie),
                AllOptData::Chain(chain) => println!("; CHAIN: {}", chain),
                AllOptData::KeyTag(keytag) => println!("; KEYTAG: {}", keytag),
                AllOptData::ExtendedError(extendederror) => println!("; EDE: {}", extendederror),
                _ => println!("NO OPT!"),
            }
        }
    }
}


struct BoreError {
    msg: String,
}

impl From<&str> for BoreError {
    fn from(err: &str) -> Self {
        BoreError { msg: err.to_string() }
    }
}

impl From<io::Error> for BoreError {
    fn from(err: io::Error) -> Self {
        BoreError { msg: err.to_string() }
    }
}

impl fmt::Display for BoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.msg)
    }
}


fn main() {
    let args = GlobalParamArgs::parse();

    println!("DNAME: {}", args.qname);

    let request = match Request::configure(args) {
        Ok(request) => request,
        Err(err) => {
            println!("Bore configure error: {}", err);
            process::exit(1);
        }
    };

    if let Err(err) = request.process() {
        println!("Bore process error: {}", err);
        process::exit(1);
    }
}

