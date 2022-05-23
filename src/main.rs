extern crate domain;
extern crate clap;

use std::str::FromStr;
use std::net::{UdpSocket, IpAddr};
use clap::{Arg,Command};

use domain::base::{
	Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget,
	iana::OptionCode, octets::OctetsBuilder, message::Message,
	opt::AllOptData
};
use domain::rdata::AllRecordData;



fn main() {
	let mut qname: String = "".to_string();
	let mut server: String = "127.0.0.1".to_string();
	let mut port: u16 = 9999;

	// Get command line arguments
	let args = Command::new("bore")
		.version("0.1")
		.about("A Rusty cousin to drill")
		.author("NLnet Labs")
		.args(&[
			Arg::new("server")
				.help("The server that is queried")
				.short('s')
				.long("server")
				.takes_value(true),
			Arg::new("port")
				.help("The port of the receiving server that is queried")
				.short('p')
				.long("port")
				.takes_value(true),
			Arg::new("qname")
		]).get_matches();

	// @TODO clean this up -> Arg.validator()
	if args.is_present("port") && args.value_of("port").unwrap().chars().all(char::is_numeric) {
		port = args.value_of("port").unwrap().to_string().parse::<u16>().unwrap();
	}

	if args.is_present("server") {
		// @TODO find cleaner way to check for an IP address?
		let _: IpAddr = args.value_of("server").unwrap()
			.parse()
			.expect("Unable to parse socket address");
		server = args.value_of("server").unwrap().to_string();
	}

	if args.is_present("qname") {
		let q = args.value_of("qname").unwrap().to_string();

		if q.is_empty() {
			qname = ".".to_string();
		}
		else if !q.contains(".") {
			qname = q + ".";
		}
		else {
			qname = q;
		}
	}

	// Bind a UDP socket to an arbitrary port
	let socket = UdpSocket::bind("127.0.0.1:43210").expect("couldn't bind to address");

	let message = create_message(qname);

	let server_tuple = (server, port);

	// Send message off to the server using our socket
	socket.send_to(&message.as_dgram_slice(), server_tuple).unwrap();

	// Create recv buffer
	let mut buffer = vec![0; 1232];

	// Recv in buffer
	socket.recv_from(&mut buffer).unwrap();

	// Parse
	let response = match Message::from_octets(buffer){
		Ok(response) => Some(response),
		Err(_) => None,
	}.unwrap();

	print_response(response);

	/* Print message information */
	// println!(":: SERVER: {}", &server);

}

fn create_message(qname: String) -> StreamTarget<Vec<u8>> {
	// Make a domain name we can use later on.
	let name = Dname::<Vec<u8>>::from_str(&qname).unwrap();

// @TODO create the sections individually to gain more control/flexibility

	// Create a message builder wrapping a compressor wrapping a stream
	// target.
	let mut msg = MessageBuilder::from_target(
		StaticCompressor::new(
			StreamTarget::new_vec()
		)
	).unwrap();

	// Set the RD bit and a random IDin the header and proceed to
	// the question section.
	msg.header_mut().set_rd(true);
	msg.header_mut().set_random_id();
	let mut msg = msg.question();

	// Add a question and proceed to the answer section.
	msg.push((&name, Rtype::A)).unwrap();

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
	msg.finish().into_target()
}

fn print_response(response: Message<Vec<u8>>) {
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