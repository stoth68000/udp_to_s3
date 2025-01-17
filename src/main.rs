use crossbeam_queue::SegQueue;
use pcap::{Capture};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::env;
use chrono::Local;
use aws_sdk_s3;
use aws_sdk_s3::{Client, Config};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::config::{Region, Credentials};
use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

const SEGMENT_SIZE: usize = 500; // Number of UDP frames per segment

type Frame = Vec<u8>; // Alias for a single frame
type Segment = Vec<Frame>; // Alias for a segment (group of frames)

#[derive(Parser)]
struct Args {
    /// The value to be shown when using --showme
    #[arg(long, short, default_value_t = 1)]
    verbose: u8,
    #[arg(long)]
    interface: Option<String>,
    #[arg(long)]
    input: Option<String>,
}

fn parse_udp_url(url: &str) -> Result<(IpAddr, u16), &'static str> {
    // Check if the URL starts with 'udp://'
    if !url.starts_with("udp://") {
        return Err("URL must start with 'udp://'");
    }

    // Remove the 'udp://' prefix
    let url = &url[6..];

    // Split the remaining string at the colon to get the IP address and port
    let mut parts = url.split(':');
    let ip_str = parts.next().ok_or("No IP address found")?;
    let port_str = parts.next().ok_or("No port found")?;

    // Parse the IP address
    let ip = IpAddr::from_str(ip_str).map_err(|_| "Invalid IP address")?;

    // Parse the port
    let port = port_str.parse::<u16>().map_err(|_| "Invalid port")?;

    Ok((ip, port))
}

/// Extracts the UDP payload from a raw Ethernet packet
fn extract_udp_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 42 {
        return None; // Not large enough to contain Ethernet + IP + UDP headers
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None; // Not an IPv4 packet
    }

    let ip_header_length = (data[14] & 0x0F) as usize * 4;
    if data.len() < 14 + ip_header_length + 8 {
        return None; // Not large enough to contain IP + UDP headers
    }

    let protocol = data[23];
    if protocol != 17 {
        return None; // Not a UDP packet
    }

    let udp_header_start = 14 + ip_header_length;
    let udp_payload_start = udp_header_start + 8;
    Some(&data[udp_payload_start..])
}

fn usage()
{
    println!("Usage");
    println!("  --input     udp://227.1.1.:4001");
    println!("  --interface eno2");
    println!("  --verbose   <level 0..9>");
}

#[tokio::main]
async fn main() {

    let args = Args::parse();
    let num_args = std::env::args().count() - 1;

    if num_args == 0 {
        usage();
        return;
    }
    
    let interface_name = args.interface.unwrap_or_else(|| {
        eprintln!("No value provided for --interface");
        std::process::exit(1);
    });
    println!("interface: {}", interface_name);

    let url = args.input.unwrap_or_else(|| {
        eprintln!("No value provided for --input");
        std::process::exit(1);
    });

    let mut ip: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut port: u16 = 0;
    match parse_udp_url(&url) {
        Ok((a_ip, a_port)) => {
            println!("IP Address: {}, Port: {}", a_ip, a_port);
            ip = a_ip;   // Assign the parsed IP
            port = a_port; // Assign the parsed port
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    if args.verbose > 0 {
        println!("verbose enabled, ip {} port {}", ip, port);
    }

    // Shared queue for storing received frames
    let queue = Arc::new(SegQueue::new());

    // Clone the queue handle for the receiver thread
    let queue_receiver = Arc::clone(&queue);

    let minio_endpoint = env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let region         = env::var("MINIO_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let access_key     = env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string());
    let secret_key     = env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "ThisIsSecret12345.".to_string());
    let bucket_name    = env::var("MINIO_BUCKET_NAME").unwrap_or_else(|_| "demobucketname".to_string());

    let credentials = Credentials::new(
        &access_key, 
        &secret_key, 
        None, // session token
        None, // expires after
	    "ltn" // provider name
    );
    if args.verbose > 1 {
        println!("credentials: {:?}", credentials);
    }

    // Initialize AWS SDK S3 client
    let config = Config::builder()
        .region(Region::new(region))
        .endpoint_url(minio_endpoint)
        .credentials_provider(credentials)
        .build();
    if args.verbose > 1 {
        println!("config: {:?}", config);
    }

    let s3_client = Client::from_conf(config);
    if args.verbose > 1 {
        println!("s3_client: {:?}", s3_client);
    }

    // Spawn a thread for capturing UDP frames
    let capture_thread = thread::spawn(move || {

        // Open the default network device
        let mut cap = Capture::from_device(interface_name.as_str())
            .expect("Failed to open device")
            .promisc(true)
            .timeout(1000)
            .open()
            .expect("Failed to open capture");

        let filter = format!("host {} && port {}", ip, port);

        cap.filter(&filter, true).expect("Error setting filter");

        while let Ok(packet) = cap.next_packet() {
            let data = packet.data;
            if let Some(udp_payload) = extract_udp_payload(data) {
                if udp_payload.len() != (7 * 188) {
                    println!("Captured TS packet len: {:?}, not 7 * 188, warning", udp_payload.len());
                }
                queue_receiver.push(udp_payload.to_vec()); // Push the frame onto the queue
            }
        }
    });

    // Clone the queue handle for the sender thread
    let queue_sender = Arc::clone(&queue);

    // Spawn a thread for processing and uploading segments
    let sender_thread = thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let mut segment: Segment = Vec::new();

            loop {
                // Collect frames into a segment
                //println!("queue_sender size: {:?}", queue_sender.len());

                // Hold 3000 UDP frames until we process, ~394KB (3Mb)
                if queue_sender.len() < 300 {
                    thread::sleep(Duration::from_millis(250));
                    continue;    
                }

                while let Some(frame) = queue_sender.pop() {
                    segment.push(frame);
                    if segment.len() >= SEGMENT_SIZE {
                        break;
                    }
                }
                if segment.len() < SEGMENT_SIZE {
                    continue;
                }

                // If there are frames in the segment, upload it
                if !segment.is_empty() {

                    //println!("sending segment len: {:?}", segment.len());

                    let start = SystemTime::now();
                    let mut ms = 0;
                    match start.duration_since(UNIX_EPOCH) {
                        Ok(duration) => {
                            ms = duration.as_millis();
                        }
                        Err(e) => {
                            println!("Error: {:?}", e);
                        }
                    }
                    let body = segment.concat(); // Flatten segment into a single byte vector
                    let key = format!("segment-{}.bin", ms);
                    let blen = body.len();

                    let now = Local::now();

                    //println!("Captured body: {:?}", body);
                    match s3_client
                        .put_object()
                        .bucket(&bucket_name)
                        .key(&key)
                        .body(ByteStream::from(body))
                        .send()
                        .await
                    {
                        Ok(_) => {
                            if args.verbose > 0 {
                                println!("{:?} - Uploaded segment to S3: {}, size {:?}", now, key, blen);
                            }
                        },
                        Err(e) => eprintln!("{:?} - Failed to upload segment to S3: {}", now, e),
                    }

                    segment.clear(); // Clear the segment after upload
                }
            }
        });
    });

    // Wait for threads to finish (in a real application, you'd handle shutdown more gracefully)
    capture_thread.join().expect("Capture thread panicked");
    sender_thread.join().expect("Sender thread panicked");
}
