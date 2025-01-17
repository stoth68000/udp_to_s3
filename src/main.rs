use crossbeam_queue::SegQueue;
use pcap::{Capture};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::env;
use aws_sdk_s3::{Client, Config};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3;
use aws_sdk_s3::config::{Region, Credentials};

const SEGMENT_SIZE: usize = 10; // Number of UDP frames per segment
const UPLOAD_INTERVAL: Duration = Duration::from_secs(5); // Interval between uploads

type Frame = Vec<u8>; // Alias for a single frame
type Segment = Vec<Frame>; // Alias for a segment (group of frames)

#[tokio::main]
async fn main() {
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
    //println!("credentials: {:?}", credentials);

    // Initialize AWS SDK S3 client
    let config = Config::builder()
        .region(Region::new(region))
        .endpoint_url(minio_endpoint)
        .credentials_provider(credentials)
        .build();
    //println!("config: {:?}", config);

    let s3_client = Client::from_conf(config);
    //println!("s3_client: {:?}", s3_client);

    // Spawn a thread for capturing UDP frames
    let capture_thread = thread::spawn(move || {
        // Open the default network device
        let mut cap = Capture::from_device("eno2")
            .expect("Failed to open device")
            .promisc(true)
            .timeout(1000)
            .open()
            .expect("Failed to open capture");

        let filter = "host 227.1.20.90 && port 4010";
        cap.filter(filter, true).expect("Error setting filter");

        while let Ok(packet) = cap.next_packet() {
            let data = packet.data.to_vec(); // Convert packet data to a vector
            //println!("Captured packet: {:?}", data);
            queue_receiver.push(data); // Push the frame onto the queue
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
                while let Some(frame) = queue_sender.pop() {
                    segment.push(frame);
                    if segment.len() >= SEGMENT_SIZE {
                        break;
                    }
                }

                // If there are frames in the segment, upload it
                if !segment.is_empty() {
                    let key = format!("segment-{}.bin", chrono::Utc::now().timestamp());
                    let body = segment.concat(); // Flatten segment into a single byte vector

                    match s3_client
                        .put_object()
                        .bucket(&bucket_name)
                        .key(&key)
                        .body(ByteStream::from(body))
                        .send()
                        .await
                    {
                        Ok(_) => println!("Uploaded segment to S3: {}", key),
                        Err(e) => eprintln!("Failed to upload segment to S3: {}", e),
                    }

                    segment.clear(); // Clear the segment after upload
                }

                // Wait for the next upload interval
                thread::sleep(UPLOAD_INTERVAL);
            }
        });
    });

    // Wait for threads to finish (in a real application, you'd handle shutdown more gracefully)
    capture_thread.join().expect("Capture thread panicked");
    sender_thread.join().expect("Sender thread panicked");
}
