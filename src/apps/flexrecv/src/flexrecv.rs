#[allow(unused_extern_crates)]
extern crate m3impl as m3;

mod app;
mod datamessage;
mod fec;
mod modulation;

use crate::app::m3demo::*;
use m3impl::tiles::Activity;
use num_complex::Complex;
use std::{io, net::UdpSocket};
use std::{thread, time};

use crate::{
    datamessage::{RawDataMessage, SampleDataMessage},
    modulation::qam::{PowerNormalization, QAMOrder, QamDemapperHard, QamMapper},
};

#[no_mangle]
pub fn main() -> i32 {
    //udp
    let socket =
        UdpSocket::bind("192.168.181.56:3000").expect("Fehler beim Erstellen des UDP sockets");
    socket
        .connect("192.168.181.48:8847")
        .expect("Fehler beim setzen der Zieladresse des UDP sockets");

    //modulator
    let mut sender = M3Sender::new(8, QAMOrder::QAM16, 64);

    //send data
    loop {
        // thread::sleep(time::Duration::from_millis(1000));
        let end = time::Instant::now() + time::Duration::from_millis(100);
        while time::Instant::now() < end {}

        // Activity::own()
        //     .sleep_for(time::Duration::from_millis(100))
        //     .unwrap();
        let text = String::from("abcdefghij");
        println!("zu sendender Text: {}, Bytes: {:?}", text, text.as_bytes());

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

        // send the samples
        // the first packet has a 5 item header
        // the following packets have a 3 item header
        let max_num_samples_packet = 128;
        let num_samples_to_send = samples.get_number_of_samples();
        let num_packets = if num_samples_to_send % max_num_samples_packet == 0 {
            num_samples_to_send / max_num_samples_packet
        }
        else {
            (num_samples_to_send / max_num_samples_packet) + 1
        };
        let mut num_samples_sent = 0;

        //create a buffer
        //each sample has two float values (real and imaginary part of the number), each is written as 4 bytes
        let mut buffer: Vec<u8> = vec![0; 5 * 4 + max_num_samples_packet * 2 * 4];

        //send the first packet
        let mut num_packet = 1;
        let num_samples_packet = if num_samples_to_send > max_num_samples_packet {
            max_num_samples_packet
        }
        else {
            num_samples_to_send
        };
        let header: [f32; 5] = [4.0, num_packets as f32, num_packet as f32, 1.0, 0.0];
        buffer[0..4].copy_from_slice(&header[0].to_be_bytes());
        buffer[4..8].copy_from_slice(&header[1].to_be_bytes());
        buffer[8..12].copy_from_slice(&header[2].to_be_bytes());
        buffer[12..16].copy_from_slice(&header[3].to_be_bytes());
        buffer[16..20].copy_from_slice(&header[4].to_be_bytes());
        let last_sample_byte = 20 + num_samples_packet * 8;
        for i in (20..last_sample_byte).step_by(8) {
            buffer[i..i + 4]
                .copy_from_slice(&samples.get_sample_data()[num_samples_sent].re.to_be_bytes());
            buffer[i + 4..i + 8]
                .copy_from_slice(&samples.get_sample_data()[num_samples_sent].im.to_be_bytes());
            num_samples_sent += 1;
        }

        //print and send the packet
        println!("udp data packet {}:", num_packet);
        for i in (0..last_sample_byte).step_by(4) {
            println!(
                "{}_{}_{}_{}",
                buffer[i],
                buffer[i + 1],
                buffer[i + 2],
                buffer[i + 3]
            );
        }
        socket
            .send(&buffer[..last_sample_byte])
            .expect("Fehler beim senden der UDP Daten.");

        // send further packets with a 3 item header
        while num_samples_sent < num_samples_to_send {
            num_packet += 1;
            let num_samples_remaining = num_samples_to_send - num_samples_sent;
            let num_samples_packet = if num_samples_remaining > max_num_samples_packet {
                max_num_samples_packet
            }
            else {
                num_samples_remaining
            };
            let header: [f32; 3] = [4.0, num_packets as f32, num_packet as f32];
            buffer[0..4].copy_from_slice(&header[0].to_be_bytes());
            buffer[4..8].copy_from_slice(&header[1].to_be_bytes());
            buffer[8..12].copy_from_slice(&header[2].to_be_bytes());
            let last_sample_byte = 12 + num_samples_packet * 8;
            for i in (12..last_sample_byte).step_by(8) {
                buffer[i..i + 4]
                    .copy_from_slice(&samples.get_sample_data()[num_samples_sent].re.to_be_bytes());
                buffer[i + 4..i + 8]
                    .copy_from_slice(&samples.get_sample_data()[num_samples_sent].im.to_be_bytes());
                num_samples_sent += 1;
            }

            //print and send the packet
            println!("udp data packet {}:", num_packet);
            for i in (0..last_sample_byte).step_by(4) {
                println!(
                    "{}_{}_{}_{}",
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3]
                );
            }
            socket
                .send(&buffer[..last_sample_byte])
                .expect("Fehler beim senden der UDP Daten.");
        }
    }
}
