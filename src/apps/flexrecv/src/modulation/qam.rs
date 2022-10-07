use std::f32::consts::SQRT_2;
use std::vec;
use std::vec::Vec;
use std::convert::TryFrom;

use num_complex::Complex;

//The QAM is composed of two PAM symbols
//The normalization of the PAM symbol amplitudes is done with normalization factors from the real QAM constellation
//the unnormalized PAM symbols have a distance of two to each other
//for example, PAM 8 has symbol amplitudes of -7, -5, -3, -1, 1, 3, 5, 7
//the maximum absolute of the pam amplitude is (numpamsymbols - 1), a value which is often used in the symbol normalization
//indexing lookup tables:
//suppose there is an array with the value xmin at index 0 and each consecutive value increases linearly with the array index
//to compute the value x from the array index: x = xmin + index * dist , dist is the distance between two elements
//to compute the index from the value x: index = ((x - xmin) / dist).round()
//Some CPUs have FMA instructions which can better compute a * b + c
//So the array indexing could be rewritten to index = ((x / dist) + ( -(xmin / dist))).round(), -(xmin / dist) could be pre-computed
//The array indexing could be rewriten as: index = ((x * distinv) + offset).round(), offset = -(xmin / dist)

#[derive(Copy, Clone, PartialEq)]
pub enum QAMOrder {
    QAM4,
    QAM16,
    QAM64,
    QAM256,
    QAM1024,
    QAM4096,
    QAM16384,
    QAM65536,
    QAM262144,
    QAM1048576,
}
impl QAMOrder {
    pub fn get_number_of_pam_bits(&self) -> u32 {
        match self {
            QAMOrder::QAM4 => 1,
            QAMOrder::QAM16 => 2,
            QAMOrder::QAM64 => 3,
            QAMOrder::QAM256 => 4,
            QAMOrder::QAM1024 => 5,
            QAMOrder::QAM4096 => 6,
            QAMOrder::QAM16384 => 7,
            QAMOrder::QAM65536 => 8,
            QAMOrder::QAM262144 => 9,
            QAMOrder::QAM1048576 => 10,
        }
    }

    pub fn get_number_of_pam_symbols(&self) -> u32 {
        2u32.pow(self.get_number_of_pam_bits())
    }

    pub fn get_number_of_qam_symbols(&self) -> u32 {
        2u32.pow(2 * self.get_number_of_pam_bits())
    }
}

#[derive(Copy, Clone)]
pub enum PowerNormalization {
    PeakPower,
    AveragePower,
    NotNormalized,
}
pub fn get_normalization_value_qam(
    qamorder: QAMOrder,
    powernormalization: PowerNormalization,
) -> f32 {
    //returns the value with which the qam symbol components have to be devided to get the desired normalization
    match powernormalization {
        PowerNormalization::PeakPower => {
            //peak power: the maximum distance of a constellation point from (0,0) should be 1
            //normfactor = sqrt(2 * maxpamamplitude^2) = sqrt(2) * maxpamamplitude = sqrt(2) * (nupamsymbols - 1)
            SQRT_2 * (qamorder.get_number_of_pam_symbols() - 1) as f32
        },
        PowerNormalization::AveragePower => {
            //average power: the average distance of all qam symbols from (0,0) should be 1
            //normfactor = sqrt((M-1) * 2/3), for example M is 16 for QAM16
            ((((qamorder.get_number_of_qam_symbols() - 1) / 3) * 2) as f32).sqrt()
        },
        PowerNormalization::NotNormalized => 1.0,
    }
}
fn get_max_amplitude_pam(qamorder: QAMOrder, powernormalization: PowerNormalization) -> f32 {
    //this function computes the maximum amplitude of one PAM line of the QAM
    //PeakPower Normalization: 1 / sqrt(2)
    let maxunnormalizedamplitude: f32 = (qamorder.get_number_of_pam_symbols() - 1) as f32;
    match powernormalization {
        PowerNormalization::PeakPower => 1.0 / SQRT_2,
        PowerNormalization::AveragePower => {
            maxunnormalizedamplitude / get_normalization_value_qam(qamorder, powernormalization)
        },
        PowerNormalization::NotNormalized => maxunnormalizedamplitude,
    }
}
fn get_distance_between_two_pam_symbols(
    qamorder: QAMOrder,
    powernormalization: PowerNormalization,
) -> f32 {
    //This function computes the distance between two PAM symbols
    //distance between two PAM symbols: 2 * maxamplitude / (numpamsymbols - 1)
    //The distance between two PAM points is:
    //unnormalized: 2
    //peak power normalization: sqrt(2) / (number of PAM symbols - 1)
    //average power normalization: (2 * unnormalizedmaxx) / (sqrt((numqamsymbols - 1) * (2/3)) * (numpamsymbols - 1))
    match powernormalization {
        PowerNormalization::PeakPower => SQRT_2 / (qamorder.get_number_of_pam_symbols() - 1) as f32,
        PowerNormalization::AveragePower => {
            2.0 / get_normalization_value_qam(qamorder, powernormalization)
        },
        PowerNormalization::NotNormalized => 2.0,
    }
}
fn convert_binary_to_gray_coding(binary: usize) -> usize {
    binary ^ binary >> 1
}
fn compute_pam_symbols(qamorder: QAMOrder, powernormalization: PowerNormalization) -> Vec<f32> {
    let numpamsymbols: usize = qamorder.get_number_of_pam_symbols() as usize;
    let mut pamsymbols: Vec<f32> = vec![0.0; numpamsymbols];
    for i in 0..numpamsymbols {
        pamsymbols[convert_binary_to_gray_coding(i)] = (-((numpamsymbols - 1) as i32)
            + 2 * i as i32) as f32
            / get_normalization_value_qam(qamorder, powernormalization);
    }
    pamsymbols
}
pub struct QamMapper {
    //the number of pam bits is used to shift half of the bits which should be mapped to a qam symbol
    numpambits: usize,

    //numpamsymbolsinusone is used to mask the bits which should be mapped.
    //example: 8 bits should be mapped to a QAM symbol. Then 2 * 4 bits are mapped to PAM symbols
    //to mask 4 bits, there should be an & operation with the bits 1111, which represent the number 15 or numpamsymbols - 1
    numpamsymbolsminusone: usize,

    //look up table with the pam symbols
    pamsymbols: Vec<f32>,
}
impl QamMapper {
    pub fn new(qamorder: QAMOrder, powernormalization: PowerNormalization) -> QamMapper {
        QamMapper {
            numpambits: qamorder.get_number_of_pam_bits() as usize,
            numpamsymbolsminusone: qamorder.get_number_of_pam_symbols() as usize - 1,
            pamsymbols: compute_pam_symbols(qamorder, powernormalization),
        }
    }

    pub fn map(&self, bits: usize) -> Complex<f32> {
        Complex::new(
            self.pamsymbols[(bits >> self.numpambits) & self.numpamsymbolsminusone],
            self.pamsymbols[bits & self.numpamsymbolsminusone],
        )
    }
}
pub struct QamDemapperHard {
    //the number of pam bits is used to shift half of the bits which should be mapped to a qam symbol
    numpambits: usize,

    //demapping formula: demapped PAM bits = binary_to_gray_coding((x * pamsymboldistinv + offset).round()) with offset = -(xmin / dist) = xmax * pamsymboldistinv
    pamsymboldistinv: f32,
    offset: f32,
}

impl QamDemapperHard {
    pub fn new(qamorder: QAMOrder, powernormalization: PowerNormalization) -> QamDemapperHard {
        //offset = -(xmin / dist) = xmax / dist = (numpamsymbols - 1) / 2 = numpamsymbols / 2 - 0.5
        QamDemapperHard {
            numpambits: usize::try_from(qamorder.get_number_of_pam_bits())
                .expect("Fehler beim casten der Anzahl der PAM Bits"),
            pamsymboldistinv: 1.0
                / get_distance_between_two_pam_symbols(qamorder, powernormalization),
            offset: (qamorder.get_number_of_pam_symbols() / 2) as f32 - 0.5,
        }
    }

    pub fn demap(&self, symbol: Complex<f32>) -> usize {
        self.demapPAM(symbol.re) << self.numpambits | self.demapPAM(symbol.im)
    }

    fn demapPAM(&self, x: f32) -> usize {
        convert_binary_to_gray_coding((x * self.pamsymboldistinv + self.offset).round() as usize)
    }
}

struct QamDemapperSoft {
    //variables used for array bound checking
    snrlinmin: f32,
    snrlinmax: f32,

    //xmax needed for bound checking the llrlut array
    xmax: f32,

    //variables needd to compute the snrlin index
    //snrlinindex = (snrlin * snrlindistinv + offset).round() * numsamples * numpambits, offset = - (xmin / dist)
    snrlindistinv: f32,
    snrlinoffset: f32,
    numsamples: usize,
    numpambits: usize,

    //variable used for computing the right sample index
    //only the positive half of the llrs is sampled, so the array starts with 0 amplitude and the sampledistoffset would be 0
    //sampleidex = (x * sampledistinv).round() * numpambits
    sampledistinv: f32,

    //the LLR look up table (llrlut) has the following layout: snrs{samples{llrs}}
    //snr0s0llr0|snr0s0llr2|snr0s1llr0|snr0s1llr2|snr1s0llr0|snr1s0llr2...
    //only the positive half of the PAM range is sampled, because all except one llrs are symmetric to the origin and the one which is not only has a sign change
    llrlut: Vec<f32>,
}
impl QamDemapperSoft {
    pub fn new(
        qamorder: QAMOrder,
        powernormalization: PowerNormalization,
        snrlinmin: f32,
        snrlinmax: f32,
        numsnrsteps: usize,
        numsamples: usize,
        llrlimitabs: f32,
    ) -> QamDemapperSoft {
        //variables
        let numpambits = qamorder.get_number_of_pam_bits() as usize;
        let snrlinvaluedist = (snrlinmax - snrlinmin)
            / (numsnrsteps
                .checked_sub(1)
                .expect("the numsnrsteps variable should be greater than 1.")) as f32;
        let sampledist = get_max_amplitude_pam(qamorder, powernormalization)
            / numsamples
                .checked_sub(1)
                .expect("the numsamples variable should be greater than 1.") as f32;

        //sample the LLR function with different snrs and amplitudes, create the look up table
        let mut llrlut = vec![0.0; numsnrsteps * numsamples * numpambits];
        for snrindex in 0..numsnrsteps {
            let snrlin = snrindex as f32 * snrlinvaluedist + snrlinmin;
            for sampleindex in 0..numsamples {
                let x = sampleindex as f32 * sampledist;
                for numpambit in 0..numpambits {
                    llrlut[snrindex * numsamples * numpambits
                        + sampleindex * numpambits
                        + numpambit] = QamDemapperSoft::compute_precise_llr(
                        qamorder,
                        powernormalization,
                        snrlin,
                        x,
                        numpambit,
                        llrlimitabs,
                    );
                }
            }
        }

        //return type
        QamDemapperSoft {
            snrlinmin,
            snrlinmax,
            xmax: get_max_amplitude_pam(qamorder, powernormalization),
            snrlindistinv: 1.0 / snrlinvaluedist,
            snrlinoffset: -(snrlinmin / snrlinvaluedist),
            numsamples,
            numpambits,
            sampledistinv: 1.0 / sampledist,
            llrlut,
        }
    }

    pub fn demap(&self, snrlin: f32, symbol: Complex<f32>, buffer: &mut [f32]) {
        //the buffer argument array should have a length equal to the number of QAM bits
        debug_assert!(buffer.len() == 2 * self.numpambits);

        //The LLR values for one symbol are written to the buffer array
        //bound check on the snrlin value
        let snrlinchecked: f32 = if snrlin < self.snrlinmin {
            self.snrlinmin
        }
        else if snrlin > self.snrlinmax {
            self.snrlinmax
        }
        else {
            snrlin
        };

        //helper variable
        let offset = self.numsamples * self.numpambits;

        //compute the snrlin index of the lut array
        let snrlinindex: usize =
            (snrlinchecked * self.snrlindistinv + self.snrlinoffset).round() as usize * offset;

        //imag part
        QamDemapperSoft::demap_pam(
            symbol.im,
            self.xmax,
            self.sampledistinv,
            &self.llrlut[snrlinindex..snrlinindex + offset],
            &mut buffer[..self.numpambits],
        );

        //real part
        QamDemapperSoft::demap_pam(
            symbol.re,
            self.xmax,
            self.sampledistinv,
            &self.llrlut[snrlinindex..snrlinindex + offset],
            &mut buffer[self.numpambits..],
        );
    }

    fn demap_pam(x: f32, xmax: f32, sampledistinv: f32, samples: &[f32], pamllrbuffer: &mut [f32]) {
        //bound checking on x, xabs should be >= 0 because of the abolute value and < xmax
        let xabs = if x > xmax { xmax } else { x.abs() };

        //helper variable
        let numpambits = pamllrbuffer.len();

        //compute the sample index
        let index: usize = (xabs * sampledistinv).round() as usize * numpambits;

        //copy llr values to the halfllrstage buffer
        pamllrbuffer.copy_from_slice(&samples[index..index + numpambits]);

        //if x is negative, change the sign of one llr
        if x < 0.0 {
            pamllrbuffer[numpambits - 1] *= -1.0;
        }
    }

    fn compute_precise_llr(
        qamorder: QAMOrder,
        powernormalization: PowerNormalization,
        snrlin: f32,
        x: f32,
        numpambit: usize,
        llrlimitabs: f32,
    ) -> f32 {
        //variables
        let pamsymbols = compute_pam_symbols(qamorder, powernormalization);
        let mut sumbits1: f32 = 0.0;
        let mut sumbits0: f32 = 0.0;

        //sum up the distances
        for (i, y) in pamsymbols.iter().enumerate() {
            let d: f32 = ((-snrlin * (y - x).powi(2)) as f32).exp();

            //check if the bit of the PAM symbol is 1
            if i >> numpambit & 1 == 1 {
                sumbits1 += d;
            }
            else {
                sumbits0 += d;
            }
        }

        //error checking on the resulting llr value
        let mut llr: f32;
        if sumbits1 == 0.0 || sumbits0 == 0.0 {
            if sumbits1 == 0.0 && sumbits0 == 0.0 {
                llr = 0.0;
            }
            else if sumbits1 == 0.0 {
                llr = -llrlimitabs as f32;
            }
            else {
                llr = llrlimitabs as f32;
            }
        }
        else {
            llr = (sumbits1 / sumbits0).ln();
            if llr.abs() > llrlimitabs as f32 {
                llr = llrlimitabs as f32;
            }
            else if llr.abs() < -llrlimitabs as f32 {
                llr = -llrlimitabs as f32;
            }
        }
        llr as f32
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use num_complex::Complex;
    use rand::Rng;
    use std::time::Instant;

    #[test]
    fn test_qam() {
        //varibales
        let numqamsymbols = 1000000;
        let snrlinsoftdemapper = 1000000.0;
        let numsamplessoftdemapper = 100000;

        //program
        println!("testing QAM performace, preparing test data...");
        let mut rng = rand::thread_rng();
        let mut originalbits: Vec<u32> = vec![0; numqamsymbols];
        let mut demappedbits: Vec<u32> = vec![0; numqamsymbols];
        let mut symbols: Vec<Complex<f32>> = vec![Complex::new(0.0, 0.0); numqamsymbols];
        for i in 0..numqamsymbols {
            originalbits[i] = rng.gen::<u32>();
        }
        let powernormalizations = [
            PowerNormalization::PeakPower,
            PowerNormalization::AveragePower,
            PowerNormalization::NotNormalized,
        ];
        let qamorders = [
            QAMOrder::QAM4,
            QAMOrder::QAM16,
            QAMOrder::QAM64,
            QAMOrder::QAM256,
            QAMOrder::QAM1024,
            QAMOrder::QAM4096,
            QAMOrder::QAM16384,
            QAMOrder::QAM65536,
            QAMOrder::QAM262144,
            QAMOrder::QAM1048576,
        ];
        for powernormalization in powernormalizations {
            let name = match powernormalization {
                PowerNormalization::PeakPower => "PeakPower",
                PowerNormalization::AveragePower => "AveragePower",
                PowerNormalization::NotNormalized => "NotNormalized",
            };
            println!("");
            println!("testing power normalization: {}", name);
            for qamorder in qamorders {
                //set up memory
                println!("testing QAM{}", qamorder.get_number_of_qam_symbols());
                let qammapper = QamMapper::new(qamorder, powernormalization);
                let demapperhard = QamDemapperHard::new(qamorder, powernormalization);
                let mut demappersoft = QamDemapperSoft::new(
                    qamorder,
                    powernormalization,
                    snrlinsoftdemapper,
                    snrlinsoftdemapper + 1.0,
                    2,
                    numsamplessoftdemapper,
                    f32::MAX / 2.0,
                );

                //test mapping
                let starttime = Instant::now();
                for i in 0..numqamsymbols {
                    symbols[i] = qammapper.map(originalbits[i] as usize);
                }
                let finishtime = starttime.elapsed();

                //compute mapping performance
                let speed: f64 = numqamsymbols as f64 / finishtime.as_micros() as f64;
                println!["mapping speed: {} MSymbol/s", speed];

                //test hard demapping
                let starttime = Instant::now();
                for i in 0..numqamsymbols {
                    demappedbits[i] = demapperhard.demap(symbols[i]) as u32;
                }
                let finishtime = starttime.elapsed();

                //compute hard demapping performance
                let speed: f64 = numqamsymbols as f64 / finishtime.as_micros() as f64;
                println!["hard demapping speed: {} MSymbol/s", speed];

                //compare results, mask only the mapped bits
                for i in 0..numqamsymbols {
                    if (originalbits[i] & 2u32.pow(2 * qamorder.get_number_of_pam_bits()) - 1)
                        != demappedbits[i]
                    {
                        panic!(
                            "Die hart demappten Daten stimmen nicht mit den originalen überein!"
                        );
                    }
                }

                //test soft demapping
                let numqambits: usize = qamorder.get_number_of_pam_bits() as usize * 2;
                let mut demappedllrs: Vec<f32> = vec![0.0; numqamsymbols * numqambits];
                let starttime = Instant::now();
                for i in 0..numqamsymbols {
                    demappersoft.demap(
                        snrlinsoftdemapper,
                        symbols[i],
                        &mut demappedllrs[i * numqambits..i * numqambits + numqambits],
                    );
                }
                let finishtime = starttime.elapsed();

                //compute soft demapping performance
                let speed: f64 = numqamsymbols as f64 / finishtime.as_micros() as f64;
                println!["soft demapping speed: {} MSymbol/s", speed];

                //compare results
                for i in 0..numqamsymbols {
                    for j in 0..numqambits {
                        let bit = if demappedllrs[i * numqambits + j] >= 0.0 {
                            1
                        }
                        else {
                            0
                        };
                        if bit != originalbits[i] >> j & 1 {
                            panic!("Die soft demappten Daten stimmen nicht mit den Originalen überein!");
                        }
                    }
                }
            }
        }
    }
}
