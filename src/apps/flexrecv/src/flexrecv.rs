#![feature(core_intrinsics)]

mod app;
mod datamessage;
mod fec;
mod modulation;

#[allow(unused_extern_crates)]
extern crate m3impl as m3;

use std::net::UdpSocket;
use std::println;
use std::string::String;
use std::thread::sleep;
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use crate::{app::m3demo::*, datamessage::RawDataMessage, modulation::qam::QAMOrder};

#[no_mangle]
pub fn main() -> i32 {
    //udp
    let socket = UdpSocket::bind("127.0.0.1:3000").expect("Fehler beim Erstellen des UDP sockets");
    socket
        .connect("127.0.0.1:1337")
        .expect("Fehler beim setzen der Zieladresse des UDP sockets");

    //modulator
    let mut sender = M3Sender::new(16, QAMOrder::QAM4, 64);

    //read user input and send it
    loop {
        //sleep
        let sleepduration = Duration::from_millis(10);
        sleep(sleepduration);

        //read input
        let mut text = String::new();
        //io::stdin().read_line(&mut text);
        //text = text.trim().to_string();
        text = String::from("abc");
        println!("eingegebener Text: {}, Bytes: {:?}", text, text.as_bytes());
        if text.eq("finish") {
            break;
        }

        //modulate the input data
        let mut data = RawDataMessage::new(text.len());
        data.access_raw_data().copy_from_slice(text.as_bytes());
        let mut samples = sender.modulateData(data);

        //print samples:
        /*
        println!("samples:");
        for i in 0 .. samples.get_number_of_samples(){
            println!("{}_", samples.get_sample_data()[i]);
        }
        */
        //samples contains the raw sample data
        let packetsize = 128;

        //create a buffer
        //each sample has two float values (real and imaginary part of the number), each is written as 4 bytes
        let mut buffer: Vec<u8> = vec![0; packetsize * 2 * 4];

        //compute the number of packets
        let numfullpackets: usize = samples.get_number_of_samples() / packetsize;
        let numsamplesleft: usize = samples.get_number_of_samples() % packetsize;

        //send the full packets
        for numpacket in 0..numfullpackets {
            //write the samples
            let mut sampledataindex = numpacket * packetsize;
            for i in (0..buffer.len()).step_by(8) {
                buffer[i..i + 4]
                    .copy_from_slice(&samples.get_sample_data()[sampledataindex].re.to_be_bytes());
                buffer[i + 4..i + 8]
                    .copy_from_slice(&samples.get_sample_data()[sampledataindex].im.to_be_bytes());
                sampledataindex += 1;
            }

            //print the packet
            println!("udp data packet {}:", numpacket);
            for i in (0..buffer.len()).step_by(4) {
                println!(
                    "{}_{}_{}_{}",
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3]
                );
            }

            // send the packet
            socket
                .send(&buffer)
                .expect("Fehler beim senden der UDP Daten.");
        }

        //send the remaining samples
        let mut sampledataindex = numfullpackets * packetsize;
        for i in (0..numsamplesleft * 2 * 4).step_by(8) {
            buffer[i..i + 4]
                .copy_from_slice(&samples.get_sample_data()[sampledataindex].re.to_be_bytes());
            buffer[i + 4..i + 8]
                .copy_from_slice(&samples.get_sample_data()[sampledataindex].im.to_be_bytes());
            sampledataindex += 1;
        }

        //print the packet
        println!("udp data packet {}:", numfullpackets);
        for i in (0..numsamplesleft * 2 * 4).step_by(4) {
            println!(
                "{}_{}_{}_{}",
                buffer[i],
                buffer[i + 1],
                buffer[i + 2],
                buffer[i + 3]
            );
        }

        //send the packet
        socket
            .send(&buffer[..numsamplesleft * 2 * 4])
            .expect("Fehler beim senden der UDP Daten.");

        //sending packets with a header
        /*
        //samples has to split up into multiple udp packets with an appropriate header
        //header: 4, number_packets, sequence_number_of_packet
        //the header values are also float values

        //specify the number of sample-bytes in a packet
        //the header adds a few additional bytes to this value
        let packetsize = 1024;

        //create a buffer
        //the header are 3 values which are also floats, so one header value is written as 4 bytes
        //each sample has two float values (real and imaginary part of the number), each is written as 4 bytes
        let mut buffer : Vec<u8> = vec![0; 5 * 4 + packetsize * 2 * 4];

        //compute the number of packets
        let numfullpackets : usize = samples.get_number_of_samples() / packetsize;
        let numsamplesleft : usize = samples.get_number_of_samples() % packetsize;
        let numpackets =
        if numsamplesleft == 0{
            numfullpackets
        }
        else{
            numfullpackets + 1
        };

        //send the full packets
        for numpacket in 0..numfullpackets{

            //write the header
            let header : [f32; 5] = [4.0, numpackets as f32, (numpacket + 1) as f32, 1.0, 0.0];
            buffer[ 0.. 4].copy_from_slice(&header[0].to_be_bytes());
            buffer[ 4.. 8].copy_from_slice(&header[1].to_be_bytes());
            buffer[ 8..12].copy_from_slice(&header[2].to_be_bytes());
            buffer[12..16].copy_from_slice(&header[3].to_be_bytes());
            buffer[16..20].copy_from_slice(&header[4].to_be_bytes());

            //write the samples
            let mut sampledataindex = numpacket * packetsize;
            for i in (20..buffer.len()).step_by(8){
                buffer[i  ..i+4].copy_from_slice(&samples.get_sample_data()[sampledataindex].re.to_be_bytes());
                buffer[i+4..i+8].copy_from_slice(&samples.get_sample_data()[sampledataindex].im.to_be_bytes());
                sampledataindex += 1;
            }

            //print the packet
            println!("udp data packet {}:", numpacket + 1);
            for i in (0 .. buffer.len()).step_by(4){
                println!("{}_{}_{}_{}", buffer[i], buffer[i+1], buffer[i+2], buffer[i+3]);
            }

            //send the packet
            socket.send(&buffer).expect("Fehler beim senden der UDP Daten.");

        }

        //send the remaining samples
        //write the header
        let header : [f32; 5] = [4.0, numpackets as f32, numpackets as f32, 1.0, 0.0];
        buffer[ 0.. 4].copy_from_slice(&header[0].to_be_bytes());
        buffer[ 4.. 8].copy_from_slice(&header[1].to_be_bytes());
        buffer[ 8..12].copy_from_slice(&header[2].to_be_bytes());
        buffer[12..16].copy_from_slice(&header[3].to_be_bytes());
        buffer[16..20].copy_from_slice(&header[4].to_be_bytes());

        //write the samples
        let mut sampledataindex = numfullpackets * packetsize;
        for i in (20 .. 20 + numsamplesleft * 2 * 4).step_by(8){
             buffer[i  ..i+4].copy_from_slice(&samples.get_sample_data()[sampledataindex].re.to_be_bytes());
             buffer[i+4..i+8].copy_from_slice(&samples.get_sample_data()[sampledataindex].im.to_be_bytes());
             sampledataindex += 1;
         }

         //print the packet
         println!("udp data packet {}:", numpackets);
         for i in (0.. 12 + numsamplesleft * 2 * 4).step_by(4){
             println!("{}_{}_{}_{}", buffer[i], buffer[i+1], buffer[i+2], buffer[i+3]);
         }

         //send the packet
         socket.send(&buffer[.. 12 + numsamplesleft * 2 * 4]).expect("Fehler beim senden der UDP Daten.");
         */
    }
    println!("Hello, world!");
    0
}
