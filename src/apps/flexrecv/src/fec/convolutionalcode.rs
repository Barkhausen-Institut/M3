use crate::datamessage::RawDataMessage;

pub fn encode_convolutional(rawdatamessage : RawDataMessage, polynomials : &[i32]) -> RawDataMessage{
    
    //importand: the polynomials should have the reversed bit order in contrast to matlab
    //example: the matlab polynomial 0o_133 in octal numbering should have the bit order of 0b1101101 in this rust verison
    //helper variables
    let inputdata = rawdatamessage.read_raw_data();
    let inputdatalength = rawdatamessage.get_data_length();
    let numbitsout = polynomials.len();
    
    //polynomial : the bit positions which are xored for one output bit
    // 1 / (number of polynomials) : the code rate 
    let mut encodeddm = RawDataMessage::new(rawdatamessage.get_data_length() * numbitsout);
    let mut outputdata = encodeddm.access_raw_data();

    //this implementation of a convolutional encoder operates on packet bits
    //an 32 bit integer number is used as delay line, so there is a maximum delay of 31 bits
    //a new bit is inserted at the bitposition 0, the old bits re shifted one position to the left
    //the bits who are older as the maximum delay do not care as they are not xored
    let mut delayline : i32 = 0;
    for i in 0 .. inputdatalength{
        for j in 0 .. 8{
            
            //delay all bits
            delayline <<= 1;
            
            //put one additional bit into the delay line, the left shift should have filled in a 0 at position 0 of the delay line
            delayline += inputdata[i] as i32 >> j & 1;

            //write the output bits
            for bitout in 0 .. numbitsout{

                //compute the output bit
                //pick the bits from the delay line which should be xored together
                let xorbits = delayline & polynomials[bitout];

                //cout the number of 1 bits in xorbits, this should be a single machine instruction (pop_count)
                //if the number of 1 bits is even, the xor operation should equal 0, else 1
                let numbits1 = xorbits.count_ones();

                //when numbits1 is even, the first bit is 0.
                //when numbits1 is odd, the first bit is 1
                //so the first bit of numbits1 is the result after xoring all 1 bits of numbits1
                let resultbit = numbits1 & 1;

                //compute the position in the output array for the result bit
                let numoutputbit = (i * 8 + j) * numbitsout;
                let numoutputbyte = numoutputbit / 8;
                let outputbitinbyte = numoutputbit % 8;
                outputdata[numoutputbyte] |= (resultbit << outputbitinbyte + bitout) as u8;

                //print debug info
                /* 
                println!("delayline: {:#08b}", delayline);
                println!("polynomial: {:#08b}", polynomials[bitout]);
                println!("xorbits: {:#08b}", xorbits);
                println!("resultbit: {:#08b}", resultbit);
                println!("resultbit:                      {}", resultbit);
                */
            }
        }
    }
    encodeddm
}

#[cfg(test)]
pub mod tests{
    use std::time::Instant;

    use rand::Rng;

    use super::encode_convolutional;
    use crate::datamessage::RawDataMessage;

    #[test]
    fn test_encoding(){

        //convolutional encode polynomials
        println!("{:#08b}", 0o133);
        println!("{:#08b}", 0o171);

        //let polynomials : [i32; 2] = [0o_133, 0o_171];
        let polynomials  = [0b1101101, 0b1001111];
        let mut rawdatamessage = RawDataMessage::new(2);
        rawdatamessage.access_raw_data()[0] = 0b00011001;
        rawdatamessage.access_raw_data()[1] = 0b10000111;
        let encodeddm = encode_convolutional(rawdatamessage, &polynomials);
        for i in 0 .. encodeddm.get_data_length(){
            print!("{:#08b}_", encodeddm.read_raw_data()[i]);
        }
    }
    
    #[test]
    fn test_performance(){
        let numbytes = 100000000;
        let mut rawdatamessage = RawDataMessage::new(numbytes);
        let mut rng = rand::thread_rng();
        for i in 0..rawdatamessage.get_data_length(){
            rawdatamessage.access_raw_data()[i] = rng.gen::<u8>();
        }

        //test encode performance
        let polynomials  = [0b1101101, 0b1001111];
        let starttime = Instant::now();
        let encodeddm = encode_convolutional(rawdatamessage, &polynomials);
        let finishtime = starttime.elapsed();

        //compute encoding performance
        let speed : f64 = numbytes as f64 / finishtime.as_micros() as f64;
        println!["encoding speed: {} MByte/s", speed];
    }
}