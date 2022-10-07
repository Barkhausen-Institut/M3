use crate::imports::{vec, Vec};
use num_complex::{Complex, Complex32};

pub struct RawDataMessage {
    //ToDO: implement functionality for bit accuracy
    rawdatabuffer: Vec<u8>,
}
impl RawDataMessage {
    pub fn new(numbytes: usize) -> RawDataMessage {
        RawDataMessage {
            rawdatabuffer: vec![0; numbytes],
        }
    }

    pub fn access_raw_data(&mut self) -> &mut [u8] {
        self.rawdatabuffer.as_mut_slice()
    }

    pub fn read_raw_data(&self) -> &[u8] {
        &self.rawdatabuffer
    }

    pub fn get_maximum_buffer_length(&self) -> usize {
        self.rawdatabuffer.capacity()
    }

    pub fn get_data_length(&self) -> usize {
        self.rawdatabuffer.len()
    }

    pub fn set_data_length(&mut self, datalength: usize) {
        if self.rawdatabuffer.capacity() < datalength {
            panic!("Die Kapazität der SampleDataMessage ist geringer als die angeforderte Anzahl an Smaples !");
        }
        self.rawdatabuffer.resize(datalength, 0);
    }
}
pub struct SampleDataMessage {
    //data format for gfdm samples:
    //the rows of data should represent subsymbols, the columns of data should represent subcarriers
    // c|c|c|c
    //s
    //s
    //in array form: s1c1|s1c2|s1c3|s1c4|s2c1|s2c2|s2c3|s2c4
    //the rows should be in the first array dimension, the columns in the second one
    //example: access 4. carrier of 2. symbol: x = data[1 * numtotalcarriers + 3]
    samplebuffer: Vec<Complex<f32>>,
}
impl SampleDataMessage {
    pub fn new(numsamples: usize) -> SampleDataMessage {
        SampleDataMessage {
            samplebuffer: vec![Complex::new(0.0, 0.0); numsamples],
        }
    }

    pub fn get_sample_data(&mut self) -> &mut [Complex<f32>] {
        self.samplebuffer.as_mut_slice()
    }

    pub fn get_maximum_buffer_length(&self) -> usize {
        self.samplebuffer.capacity()
    }

    pub fn get_number_of_samples(&self) -> usize {
        self.samplebuffer.len()
    }

    pub fn set_number_of_samples(&mut self, numsamples: usize) {
        if self.samplebuffer.capacity() < numsamples {
            panic!("Die Kapazität der SampleDataMessage ist geringer als die angeforderte Anzahl an Smaples !");
        }
        self.samplebuffer.resize(numsamples, Complex::new(0.0, 0.0));
    }
}
