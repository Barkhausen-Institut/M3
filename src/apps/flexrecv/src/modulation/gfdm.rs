use crate::datamessage::SampleDataMessage;
use num_complex::{Complex, Complex32};
use std::vec;

/// Computes `e^(self)`, where `e` is the base of the natural logarithm.
#[inline]
pub fn complex_exp(n: Complex<f32>) -> Complex<f32> {
    // formula: e^(a + bi) = e^a (cos(b) + i*sin(b)) = from_polar(e^a, b)

    let Complex { re, mut im } = n;
    // Treat the corner cases +∞, -∞, and NaN
    if re.is_infinite() {
        if re < 0.0 {
            if !im.is_finite() {
                return Complex::new(0.0, 0.0);
            }
        } else {
            if im == 0.0 || !im.is_finite() {
                if im.is_infinite() {
                    im = f32::NAN;
                }
                return Complex::new(re, im);
            }
        }
    } else if re.is_nan() && im == 0.0 {
        return n;
    }

    // from_polar
    Complex::new(re.exp() * im.cos(), re.exp() * im.sin())
}

//The GFDMTransformer struct handles modulation and demodulation by applying the transforms on the samples
pub struct GFDMTransformer{

    //dynamic array which stores the interfaces to all transformation which should be applied to the sample data
    transformations : Vec<Box<dyn Transformable>>,
}
impl GFDMTransformer
{
    pub fn compute(&mut self, sampledatamessage : &mut SampleDataMessage){
        for transformation in self.transformations.iter_mut(){
            transformation.transformSamples(sampledatamessage.get_sample_data());
        }
    }
}

//GFDM properties
#[derive(PartialEq)]
pub enum ModemMode{
    Modulation,
    Demodulation
}
pub struct GFDMProperties{
    pub modemmode : ModemMode,
    pub numsubsymbols : usize,
    pub numsubcarriers : usize,
}

// gfdmmodulator and gfdmdemodulator initialize and return a Modem struct
pub fn create_modem(properties : GFDMProperties) -> GFDMTransformer {

    //function does not yet create demodulatos, this is to do
    let mut transformations = Vec::<Box<dyn Transformable>>::new();

    //modulators
    if properties.modemmode == ModemMode::Modulation{

        //special OFDM case
        if properties.numsubsymbols == 1{

            //first compute an IFFT on the subcarriers
            transformations.push(Box::new(SubCarrierFFT::new(properties.numsubcarriers, FftDirection::Inverse)));

            //second create a window which normalizes the values
            transformations.push(Box::new(Window::new_constant_window(properties.numsubsymbols, properties.numsubcarriers, Complex::new(1.0 / (properties.numsubcarriers as f32).sqrt(), 0.0))));
        }
        else {
             //first a IFFT on the subcarriers
            transformations.push(Box::new(SubCarrierFFT::new(properties.numsubcarriers, FftDirection::Inverse)));
   
            //second a FFT on the subsymbols
            transformations.push(Box::new(SubSymbolFFT::new(properties.numsubsymbols, properties.numsubcarriers, FftDirection::Forward)));

            //third is the windowing
            transformations.push(Box::new(Window::new(properties.numsubsymbols, properties.numsubcarriers)));

            //fourth an IDFT on the subsymbols
            transformations.push(Box::new(SubSymbolFFT::new(properties.numsubsymbols, properties.numsubcarriers, FftDirection::Inverse)));
        }
    }

    //create the GFDMTransformer struct
    GFDMTransformer {
        transformations,
    }
}
trait Transformable{
    fn transformSamples(&mut self, samples : &mut [Complex<f32>]);
}

//transformations for the modem
#[derive(Clone, Copy)]
pub enum FftDirection{
    Forward,
    Inverse,
}
fn compute_fft(data : &mut [Complex32], fftdirection : FftDirection){
    let mut buffer = vec![Complex::<f32>::new(0.0, 0.0); data.len()];
    let number = match fftdirection{
        FftDirection::Forward => Complex::<f32>::new(0.0, - 2.0 * std::f32::consts::PI / data.len() as f32),
        FftDirection::Inverse => Complex::<f32>::new(0.0,   2.0 * std::f32::consts::PI / data.len() as f32)
    };

    //loop over the output elements over the transform
    for i in 0..buffer.len(){
        for j in 0..data.len(){
             buffer[i] += complex_exp(number * (i * j) as f32) * data[j];
        }
    }

    //copy the data to the original array
    data.copy_from_slice(&buffer);
}
struct SubSymbolFFT{
    numsubsymbols : usize,
    numsubcarriers : usize,
    fftdirection: FftDirection,
    sampleline: Vec<Complex<f32>>,
}
impl SubSymbolFFT{
    fn new(numsubsymbols : usize, numsubcarriers : usize, fftdirection : FftDirection) -> SubSymbolFFT{
        SubSymbolFFT{
            numsubsymbols,
            numsubcarriers,
            fftdirection,
            sampleline : vec![Complex::new(0.0, 0.0); numsubsymbols],
        }
    }
}
impl Transformable for SubSymbolFFT{
    fn transformSamples(&mut self, samples : &mut [Complex<f32>]){
        for i in 0 .. self.numsubcarriers{

            //write subsymbolsamples to temporal buffer
            for j in 0 .. self.numsubsymbols{
                self.sampleline[j] = samples[i + j * self.numsubcarriers];
            }

            //compute FFT
            compute_fft(&mut self.sampleline, self.fftdirection);

            //write the transformed samples back to the original slice
            for j in 0 .. self.numsubsymbols{
                samples[i + j * self.numsubcarriers] = self.sampleline[j];
            }
        }
    }
}
struct SubCarrierFFT{
    numsubcarriers : usize,
    fftdirection : FftDirection,
}
impl SubCarrierFFT{
    fn new(numsubcarriers : usize, fftdirection : FftDirection) -> SubCarrierFFT{
        SubCarrierFFT{
            numsubcarriers,
            fftdirection,
        }
    }
}
impl Transformable for SubCarrierFFT{
    fn transformSamples(&mut self, samples : &mut [Complex<f32>]){
        for i in (0 .. samples.len()).step_by(self.numsubcarriers){
            compute_fft(&mut samples[i .. i + self.numsubcarriers], self.fftdirection);
        }
    }
}
struct Window{
    windowvalues : Vec<Complex<f32>>,
}
impl Window{
    fn new(numsubsymbols : usize, numsubcarriers : usize) -> Window{
        Window{
            windowvalues : vec![Complex::new(1.0, 0.0); numsubsymbols * numsubcarriers],
        }
    }
    fn new_constant_window(numsubsymbols : usize, numsubcarriers : usize, constant : Complex32) -> Window{
        Window{
            windowvalues : vec![constant; numsubsymbols * numsubcarriers],
        }
    }
}
impl  Transformable for Window {
    fn transformSamples(&mut self, samples : &mut [Complex<f32>]) {
        for i in 0 .. self.windowvalues.len(){
            samples[i] *= self.windowvalues[i];
        }
    }
}

#[cfg(test)]
pub mod tests{
    use super::*;
    use num_complex::Complex;
    use rand::Rng;
    use std::time::Instant;
    
    #[test]
    fn test_gfdm(){

        //varibales
        let numdatamessages = 1000;

        //subsymbol options
        let minnumsubsymbols  = 16;
        let maxnumsubsymbols  = 16;
        let subsymbolsteps    = 1;

        //subcarrieroptions
        let minnumsubcarriers = 128;
        let maxnumsubcarriers = 128;
        let subcarriersteps   = 1;

        //program
        println!("testing GFDM performace...");
        let mut rng = rand::thread_rng();
        for numsubsymbols in (minnumsubsymbols..=maxnumsubsymbols).step_by(subsymbolsteps){
            for numsubcarriers in (minnumsubcarriers..=maxnumsubcarriers).step_by(subcarriersteps){

                //create test data
                println!("testing {} subsymbols and {} subcarriers...", numsubsymbols, numsubcarriers);
                let mut sampledatamessages = Vec::<SampleDataMessage>::new();
                let mut modulator = create_modem(GFDMProperties{modemmode : ModemMode::Modulation, numsubsymbols, numsubcarriers});
                for i in 0 .. numdatamessages{
                    let numsamples = numsubsymbols * numsubcarriers;
                    let mut sdm = SampleDataMessage::new(numsamples);
                    for j in 0 .. numsamples{
                        sdm.get_sample_data()[j] = Complex::<f32>::new(rng.gen::<f32>(), rng.gen::<f32>());
                    }
                    sampledatamessages.push(sdm);
                }

                //measure modulation time
                let starttime = Instant::now();
                for sdm in sampledatamessages.iter_mut(){
                    modulator.compute(sdm);
                }
                let finishtime = starttime.elapsed();

                //print the performance numbers
                let speed : f64 = (numdatamessages * numsubsymbols * numsubcarriers) as f64 / finishtime.as_micros() as f64;
                println!["speed: {} MSymbol/s", speed];
            }
        }
    }
}
