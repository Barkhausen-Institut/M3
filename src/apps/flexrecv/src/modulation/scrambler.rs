pub fn scramble_data_with_number_increment(data : &mut[u8]){

    //the scrambling sequence is 0, 1, 2, 3, 4, ...
    //this sequence is added to the data
    //the sequence overflow is intended
    for i in 0 .. data.len(){
        data[i] = data[i].wrapping_add(i as u8);
    }
}
pub fn descramble_data_with_number_increment(data : &mut[u8]){

    //the scrambling sequence is 0, 1, 2, 3, 4, ...
    //this sequence is subtracted from the data
    //the sequence overflow is intended
    for i in 0 .. data.len(){
        data[i] = data[i].wrapping_sub(i as u8);
    }
}

#[cfg(test)]
pub mod tests{
    use super::*;
    use rand::Rng;

    #[test]
    fn print_scrambling(){
        const DATALENGTH : usize = 400;
        let mut data : [u8; DATALENGTH] = [0; DATALENGTH];
        scramble_data_with_number_increment(&mut data);
        println!("scrambled data: ");
        for i in 0..data.len(){
            print!("{}_", data[i]);
        }
        descramble_data_with_number_increment(&mut data);
        println!("");
        println!("descrambled data: ");
        for i in 0..data.len(){
            print!("{}_", data[i]);
        }
    }

    #[test]
    fn test_scrambling(){
        const DATALENGTH : usize = 1000000;
        let mut refdata : Vec<u8> = vec![0; DATALENGTH];
        let mut rng = rand::thread_rng();

        //fill data array with random data
        for i in 0 .. refdata.len(){
            refdata[i] = rng.gen::<u8>();
        }

        //copy data for the scrambling
        let mut data = refdata.clone();

        //scramble and descramble
        scramble_data_with_number_increment(&mut data);
        descramble_data_with_number_increment(&mut data);
        
        //test if data matches
        for i in 0..DATALENGTH{
            if data[i] != refdata[i] {
                panic!("data after scrambling and descrambling does not match!");
            }
        }
    }
}
