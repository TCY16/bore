use std::{fmt, io, process};
use std::str::FromStr;
use std::net::{UdpSocket, IpAddr, SocketAddr};
use clap::{Arg,Command};

use domain::base::{
        Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget,
        iana::OptionCode, octets::OctetsBuilder, message::Message,
        opt::AllOptData
};
use domain::rdata::AllRecordData;


#[derive(Clone, Debug)]
struct Request {
    server: SocketAddr,
    qname: Dname<Vec<u8>>,
}

impl Request {
    fn from_cmd_line() -> Result<Self, String> {
        let mut server = IpAddr::from_str("127.0.0.1").unwrap(); // We know this fine.

        // Get command line arguments
        let args = Command::new("bore")
                .version("0.1")
                .about("A Rusty cousin to drill")
                .author("NLnet Labs")
                .args(&[
                    Arg::new("server")
                        .help("The server that is query is sent to")
                        .short('s')
                        .long("server")
                        .takes_value(true),
                    Arg::new("port")
                        .help("The port of the server that is query is sent to")
                        .short('p')
                        .long("port")
                        .takes_value(true),
                    Arg::new("qname")
                ]).get_matches();

        // @TODO clean this up -> Arg.validator()

        let port = args.value_of("port").and_then(|port| u16::from_str(port).ok()).unwrap_or(53);

        if args.is_present("server") {
            server = args.value_of("server").unwrap()
                .parse()
                .expect("Unable to parse server IP address");
        }
        
        let qname = match args.value_of("qname") {
            Some(qname) => Dname::from_str(qname).map_err(|err| err.to_string())?,
            None => Dname::root_vec(),
        };

        Ok(Request {
            server: (server, port).into(),
            qname
        })
    }

    fn process(self) -> Result<(), BoreError> {
        // Bind a UDP socket to a kernel-provided port
        let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

        let message = self.create_message()?;

        // Send message off to the server using our socket
        socket.send_to(&message.as_dgram_slice(), self.server)?;

        // Create recv buffer
        let mut buffer = vec![0; 1232];

        // Recv in buffer
        socket.recv_from(&mut buffer)?;

        // Parse the response
        let response = Message::from_octets(buffer).map_err(|_| "bad response")?;
        self.print_response(response);

        /* Print message information */
        // println!(":: SERVER: {}", &server);

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
        msg.push((&self.qname, Rtype::A)).unwrap();

        let mut msg = msg.additional();

        // Add an OPT record.
        msg.opt(|opt| {
            opt.set_udp_payload_size(4096);
            opt.push_raw_option(OptionCode::Nsid, |target| {
                            target.append_slice(b" ")
                    })?;
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
                // @TODO Display not implemented for these OPTs
                // AllOptData::Dau(dau) => println!("{}", dau),
                // AllOptData::Dhu(dhu) => println!("{}", dhu),
                // AllOptData::N3u(d3u) => println!("{}", n3u),
                // AllOptData::Expire(expire) => println!("{}", expire),
                // AllOptData::TcpKeepalive(tcpkeepalive) => println!("{}", tcpkeepalive),
                // AllOptData::Padding(padding) => println!("{}", padding),
                // AllOptData::ClientSubnet(clientsubnet) => println!("{}", clientsubnet),
                // AllOptData::Cookie(cookie) => println!("{}", cookie),
                // AllOptData::Chain(chain) => println!("{}", chain),
                // AllOptData::KeyTag(keytag) => println!("{}", keytag), 
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
    let request = match Request::from_cmd_line() {
        Ok(request) => request,
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    };
    if let Err(err) = request.process() {
        println!("{}", err);
        process::exit(1);
    }
}

