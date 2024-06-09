use rand::Rng;

//used so that we can mock the random number generator
pub trait Random {
    fn gen_range(&mut self, low: u8, high: u8) -> u8;
}

pub struct RealRandom;

impl Random for RealRandom {
    fn gen_range(&mut self, low: u8, high: u8) -> u8 {
        rand::thread_rng().gen_range(low..high)
    }
}
