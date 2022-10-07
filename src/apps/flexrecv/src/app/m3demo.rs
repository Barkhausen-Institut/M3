use std::vec;
use std::vec::Vec;

// use std::env;
// use std::fs::File;
// use std::io::BufRead;
// use std::io::BufReader;

use crate::datamessage::*;
use crate::fec::convolutionalcode::encode_convolutional;
use crate::modulation::gfdm::*;
use crate::modulation::qam::*;
use crate::modulation::scrambler::scramble_data_with_number_increment;
use crc::*;
use num_complex::Complex;

pub struct M3Sender {
    //crc sums
    numcrcbits: u32,
    crc8: Crc<u8>,
    crc16: Crc<u16>,
    qamorder: QAMOrder,
    qammapper: QamMapper,
    pilotsymbolindexes: Vec<usize>,
    datasymbolindexes: Vec<usize>,
    numsubcarriers: usize,
    carrierratio: f32,
    modulator: GFDMTransformer,
    preamble: Vec<Complex<f32>>,
}

static PREAMBLE: [f32; 256] = [
    0.7071, -0.7071, 0.7410, -0.6716, 0.8315, -0.5556, 0.9415, -0.3369, 1.0000, -0.0000, 0.9040,
    0.4276, 0.5556, 0.8315, -0.0491, 0.9988, -0.7071, 0.7071, -0.9988, -0.0491, -0.5556, -0.8315,
    0.4276, -0.9040, 1.0000, 0.0000, 0.3369, 0.9415, -0.8315, 0.5556, -0.6716, -0.7410, 0.7071,
    -0.7071, 0.6716, 0.7410, -0.8315, 0.5556, -0.3369, -0.9415, 1.0000, 0.0000, -0.4276, 0.9040,
    -0.5556, -0.8315, 0.9988, 0.0491, -0.7071, 0.7071, 0.0491, -0.9988, 0.5556, 0.8315, -0.9040,
    -0.4276, 1.0000, 0.0000, -0.9415, 0.3369, 0.8315, -0.5556, -0.7410, 0.6716, 0.7071, -0.7071,
    -0.7410, 0.6716, 0.8315, -0.5556, -0.9415, 0.3369, 1.0000, -0.0000, -0.9040, -0.4276, 0.5556,
    0.8315, 0.0491, -0.9988, -0.7071, 0.7071, 0.9988, 0.0491, -0.5556, -0.8315, -0.4276, 0.9040,
    1.0000, 0.0000, -0.3369, -0.9415, -0.8315, 0.5556, 0.6716, 0.7410, 0.7071, -0.7071, -0.6716,
    -0.7410, -0.8315, 0.5556, 0.3369, 0.9415, 1.0000, 0.0000, 0.4276, -0.9040, -0.5556, -0.8315,
    -0.9988, -0.0491, -0.7071, 0.7071, -0.0491, 0.9988, 0.5556, 0.8315, 0.9040, 0.4276, 1.0000,
    0.0000, 0.9415, -0.3369, 0.8315, -0.5556, 0.7410, -0.6716, 0.7071, -0.7071, 0.7410, -0.6716,
    0.8315, -0.5556, 0.9415, -0.3369, 1.0000, -0.0000, 0.9040, 0.4276, 0.5556, 0.8315, -0.0491,
    0.9988, -0.7071, 0.7071, -0.9988, -0.0491, -0.5556, -0.8315, 0.4276, -0.9040, 1.0000, 0.0000,
    0.3369, 0.9415, -0.8315, 0.5556, -0.6716, -0.7410, 0.7071, -0.7071, 0.6716, 0.7410, -0.8315,
    0.5556, -0.3369, -0.9415, 1.0000, 0.0000, -0.4276, 0.9040, -0.5556, -0.8315, 0.9988, 0.0491,
    -0.7071, 0.7071, 0.0491, -0.9988, 0.5556, 0.8315, -0.9040, -0.4276, 1.0000, 0.0000, -0.9415,
    0.3369, 0.8315, -0.5556, -0.7410, 0.6716, 0.7071, -0.7071, -0.7410, 0.6716, 0.8315, -0.5556,
    -0.9415, 0.3369, 1.0000, -0.0000, -0.9040, -0.4276, 0.5556, 0.8315, 0.0491, -0.9988, -0.7071,
    0.7071, 0.9988, 0.0491, -0.5556, -0.8315, -0.4276, 0.9040, 1.0000, 0.0000, -0.3369, -0.9415,
    -0.8315, 0.5556, 0.6716, 0.7410, 0.7071, -0.7071, -0.6716, -0.7410, -0.8315, 0.5556, 0.3369,
    0.9415, 1.0000, 0.0000, 0.4276, -0.9040, -0.5556, -0.8315, -0.9988, -0.0491, -0.7071, 0.7071,
    -0.0491, 0.9988, 0.5556, 0.8315, 0.9040, 0.4276, 1.0000, 0.0000, 0.9415, -0.3369, 0.8315,
    -0.5556, 0.7410, -0.6716,
];

impl M3Sender {
    pub fn new(numcrcbits: u32, qamorder: QAMOrder, numsubcarriers: usize) -> M3Sender {
        if numcrcbits != 8 && numcrcbits != 16 {
            panic!("wrong number of crc bits!");
        }

        //the receiver supports QAM4, QAM16 and QAM64
        if qamorder != QAMOrder::QAM4 && qamorder != QAMOrder::QAM16 {
            panic!("wrong QAM order!");
        }

        //the receiver supports OFDM64 or OFDM1024
        if numsubcarriers != 64 && numsubcarriers != 1024 {
            panic!("wrong number of OFDM subcrriers!");
        }

        //store the pilot symgol indexes
        let pilotsymbolindexes = if numsubcarriers == 64 {
            vec![9, 22, 41, 54]
        }
        else {
            vec![115, 227, 339, 451, 573, 685, 797, 909]
        };

        //zeros in the symbl
        let (dcgap, edge0) = if numsubcarriers == 64 {
            (6, 3)
        }
        else {
            (10, 59)
        };

        //store the data symbol indexes
        let mut datasymbolindexes: Vec<usize> = Vec::new();
        'loop1: for i in edge0..(numsubcarriers - edge0) {
            //if the index should be a pilot
            for pilotsymbolindex in &pilotsymbolindexes {
                if i == *pilotsymbolindex {
                    continue 'loop1;
                }
            }

            //if the index should not be 0
            if i < (numsubcarriers - dcgap) / 2 || i >= (numsubcarriers + dcgap) / 2 {
                datasymbolindexes.push(i);
            }
        }

        //Debug
        //println!("datasymbolindexes: {:?}", datasymbolindexes);
        //Debug fertig

        //compute the carrier ratio
        let carrierratio = numsubcarriers as f32 / (numsubcarriers - dcgap - 2 * edge0) as f32;

        //read the preamble
        let mut preamble: Vec<Complex<f32>> = Vec::new();
        // let mut stringlines = Vec::new();
        // let file = BufReader::new(
        //     File::open("src/app/preamble.txt").expect("Fehler beim Öffnen der preambel Datei"),
        // );

        // let lines = file.lines();
        // for line in lines {
        //     match line {
        //         Ok(l) => stringlines.push(l.replace(" ", "")),
        //         Err(_) => panic!("Fehler in der preamble Datei"),
        //     }
        // }
        for i in 0..PREAMBLE.len() / 2 {
            preamble.push(Complex::new(PREAMBLE[i * 2], PREAMBLE[i * 2 + 1]));
        }

        //boost premable
        for i in 0..preamble.len() {
            preamble[i] *= 8.0;
        }

        M3Sender {
            numcrcbits,
            crc8: Crc::<u8>::new(&CRC_8_GSM_B),
            crc16: Crc::<u16>::new(&CRC_16_XMODEM),
            qamorder,
            qammapper: QamMapper::new(qamorder, PowerNormalization::AveragePower),
            pilotsymbolindexes,
            datasymbolindexes,
            numsubcarriers,
            carrierratio,
            modulator: create_modem(GFDMProperties {
                modemmode: ModemMode::Modulation,
                numsubsymbols: 1,
                numsubcarriers,
            }),
            preamble,
        }
    }

    pub fn modulateData(&mut self, mut rawdatamessage: RawDataMessage) -> SampleDataMessage {
        //check the length of the data message

        //do the bit scrambling
        scramble_data_with_number_increment(rawdatamessage.access_raw_data());

        /*
        println!("data after scrambling:");
        for i in 0 .. rawdatamessage.get_data_length(){
            println!("{}_", rawdatamessage.read_raw_data()[i]);
        }
        */

        //compute the crc sum
        let mut crcdatamessage: RawDataMessage = if self.numcrcbits == 8 {
            let mut tempdatamessage = RawDataMessage::new(rawdatamessage.get_data_length() + 1);
            for i in 0..rawdatamessage.get_data_length() {
                tempdatamessage.access_raw_data()[i] = rawdatamessage.read_raw_data()[i];
            }

            //compute the 8 bit crc value
            let crc8data = self.crc8.checksum(rawdatamessage.read_raw_data()) ^ 255;
            let mut data = tempdatamessage.access_raw_data();
            data[data.len() - 1] = crc8data;

            //Debug
            //println!("crc checksumme: {:#08b}", crc8data);
            //Debug fertig

            tempdatamessage
        }
        else {
            let mut tempdatamessage = RawDataMessage::new(rawdatamessage.get_data_length() + 2);
            for i in 0..rawdatamessage.get_data_length() {
                tempdatamessage.access_raw_data()[i] = rawdatamessage.read_raw_data()[i];
            }

            //compute the 16 bit crc value
            let crc16data = self.crc16.checksum(rawdatamessage.read_raw_data());
            let mut data = tempdatamessage.access_raw_data();
            data[data.len() - 2] = (crc16data >> 8 & 255) as u8;
            data[data.len() - 1] = (crc16data & 255) as u8;

            //Debug
            //println!("crc checksumme: {:#016b}", crc16data);
            //Debug fertig

            tempdatamessage
        };

        /*
        println!("data with the crc checksum:");
        for i in 0 .. crcdatamessage.get_data_length(){
            println!("{}_", crcdatamessage.read_raw_data()[i]);
        }
        */

        //do the fec coding
        //padd one zero byte at the end
        let mut paddeddm = RawDataMessage::new(crcdatamessage.get_data_length() + 1);
        for i in 0..crcdatamessage.get_data_length() {
            paddeddm.access_raw_data()[i] = crcdatamessage.read_raw_data()[i];
        }

        //polynomials: 0o_171, 0o_133 in reverse bit order
        let polynomials = [0b1001111, 0b1101101];
        let mut codeddm = encode_convolutional(paddeddm, &polynomials);

        //reverse the bits (0b00000001 gets reversed to 0b10000000)
        for i in 0..codeddm.get_data_length() {
            let mut temp: u8 = 0;
            for j in 0..8 {
                temp |= (codeddm.read_raw_data()[i] >> j & 1) << (7 - j);
            }
            codeddm.access_raw_data()[i] = temp;
        }

        /*
        println!("fec coded data:");
        for i in 0 .. codeddm.get_data_length(){
            println!("{}_", codeddm.read_raw_data()[i]);
        }
        */

        //do the QAM mapping
        let mut qamsymbols = if self.qamorder == QAMOrder::QAM4 {
            //QAM4
            let mut tempsdm = SampleDataMessage::new(codeddm.get_data_length() * 4);
            for i in 0..codeddm.get_data_length() {
                //each byte has data for 4 samples, 1 sample equals 2 bits with QAM4
                //in the matlab version, the first bit is mapped to the imaginary part of the symbol and the second (less significant) bit to the real part of the symbol
                //so the even and odd bits have to be swapped to comply with the matlab version
                let evenbits: u8 = codeddm.read_raw_data()[i] & 0b10101010;
                let oddbits: u8 = codeddm.read_raw_data()[i] & 0b01010101;
                let swappedbits = evenbits >> 1 ^ oddbits << 1;
                tempsdm.get_sample_data()[4 * i] = self.qammapper.map((swappedbits >> 6) as usize);
                tempsdm.get_sample_data()[4 * i + 1] =
                    self.qammapper.map((swappedbits >> 4) as usize);
                tempsdm.get_sample_data()[4 * i + 2] =
                    self.qammapper.map((swappedbits >> 2) as usize);
                tempsdm.get_sample_data()[4 * i + 3] = self.qammapper.map(swappedbits as usize);
            }
            tempsdm
        }
        else {
            //QAM16
            let mut tempsdm = SampleDataMessage::new(codeddm.get_data_length() * 2);
            for i in 0..codeddm.get_data_length() {
                //each byte has data for 2 samples, 1 sample equals 4 bits with QAM16
                tempsdm.get_sample_data()[2 * i] = self
                    .qammapper
                    .map((codeddm.read_raw_data()[i] >> 4) as usize);
                tempsdm.get_sample_data()[2 * i + 1] =
                    self.qammapper.map(codeddm.read_raw_data()[i] as usize);
            }
            tempsdm
        };

        /*
        println!("QAM mapped data:");
        for i in 0 .. qamsymbols.get_number_of_samples(){
            println!("{}_", qamsymbols.get_sample_data()[i]);
        }
        */

        let mut sampledatamessage = SampleDataMessage::new(self.numsubcarriers);

        //set pilot carriers
        for i in 0..self.pilotsymbolindexes.len() {
            sampledatamessage.get_sample_data()[self.pilotsymbolindexes[i]] =
                Complex::new(1.0, 0.0);
        }

        //set the data symbols
        let numsymbolstoallocate = core::cmp::min(
            qamsymbols.get_number_of_samples(),
            self.datasymbolindexes.len(),
        );
        for i in 0..numsymbolstoallocate {
            sampledatamessage.get_sample_data()[self.datasymbolindexes[i]] =
                qamsymbols.get_sample_data()[i];
        }

        /*
        println!("symbol data before modulation:");
        for i in 0 .. sampledatamessage.get_number_of_samples(){
            println!("{}_", sampledatamessage.get_sample_data()[i]);
        }
        */

        //do the modulation
        self.modulator.compute(&mut sampledatamessage);

        //apply the carrier ratio
        for symbol in sampledatamessage.get_sample_data() {
            *symbol *= Complex::new(self.carrierratio.sqrt(), 0.0);
        }

        /*
        println!("symbol data after modulation:");
        for i in 0 .. sampledatamessage.get_number_of_samples(){
            println!("{}_", sampledatamessage.get_sample_data()[i]);
        }
        */

        //add the preamble, the CP and CS
        let cpl = 32;
        let csl = 15;
        let mut frame = SampleDataMessage::new(
            cpl + self.preamble.len() + csl + cpl + self.numsubcarriers + csl,
        );

        //preamble data
        frame.get_sample_data()[0..cpl]
            .copy_from_slice(&self.preamble[self.preamble.len() - cpl..]);
        frame.get_sample_data()[cpl..cpl + self.preamble.len()].copy_from_slice(&self.preamble[..]);
        frame.get_sample_data()[cpl + self.preamble.len()..cpl + self.preamble.len() + csl]
            .copy_from_slice(&self.preamble[..csl]);

        //frame data
        frame.get_sample_data()
            [cpl + self.preamble.len() + csl..cpl + self.preamble.len() + csl + cpl]
            .copy_from_slice(&sampledatamessage.get_sample_data()[self.numsubcarriers - cpl..]);
        frame.get_sample_data()[cpl + self.preamble.len() + csl + cpl
            ..cpl + self.preamble.len() + csl + cpl + sampledatamessage.get_number_of_samples()]
            .copy_from_slice(&sampledatamessage.get_sample_data()[..]);
        frame.get_sample_data()
            [cpl + self.preamble.len() + csl + cpl + sampledatamessage.get_number_of_samples()..]
            .copy_from_slice(&sampledatamessage.get_sample_data()[..csl]);

        /*
        println!("frame data:");
        for i in 0 .. frame.get_number_of_samples(){
            println!("{}_", frame.get_sample_data()[i]);
        }
        */

        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reftest_m3() {
        //test reference data
        let mut sender = M3Sender::new(16, QAMOrder::QAM4, 64);

        //reference data:
        //OFDM64,   QAM4,  CRC16:   3 Bytes
        //OFDM64,   QAM4,  CRC8:    4 Bytes
        //OFDM64,   QAM16, CRC16:   9 Bytes
        //OFDM64,   QAM16, CRC16:  10 Bytes
        //OFDM1024, QAM4,  CRC16: 108 Byte
        //OFDM1024, QAM4,  CRC8:  109 Byte
        //OFDM1024, QAM16, CRC16: 219 Byte
        //OFDM1024, QAM16, CRC8:  220 Byte
        let mut refdatamessage = RawDataMessage::new(3);
        for i in 0..refdatamessage.get_data_length() {
            refdatamessage.access_raw_data()[i] = i as u8 + 1;
        }
        sender.modulateData(refdatamessage);
    }
}
