use crate::rnd::Random;
use gf::GF256;
use std::collections::HashMap;

mod rnd;

pub fn sss(secret: &str, threshold: u8, shares_num: u8) -> Vec<(u8, Vec<(u8, u8)>)> {
    let mut shares = Vec::new();
    let mut counter = 0;

    secret.as_bytes().iter().for_each(|byte| {
        let polynomial = generate_polynomial(&mut rnd::RealRandom, threshold-1, *byte);
        let s = calculate_shares(&mut rnd::RealRandom, &polynomial, shares_num);
        shares.push((counter, s));
        counter += 1;
    });

    shares
}

pub fn recover(shares: &mut Vec<(u8, Vec<(u8, u8)>)>) -> String {

    shares.sort_by(|a, b | a.0.cmp(&b.0));

    let mut secret = Vec::new();
    shares.iter().for_each(|s| {
        let byte = lagrange_interpolation(&s.1);
        secret.push(byte)
    });


    String::from_utf8(secret).unwrap()
}

/// Generate a random polynomial of degree X with the secret as the last coefficient
fn generate_polynomial<R: Random>(rng: &mut R, degree: u8, secret: u8) -> Vec<u8> {
    let mut polynomial = Vec::new();

    for _ in 0..degree {
        polynomial.push(rng.gen_range(0, 255));
    }
    polynomial.push(secret);
    polynomial
}

/// Calculate the shares for the given polynomial
fn calculate_shares<R: Random>(rng: &mut R, polynomial: &Vec<u8>, shares_num: u8) -> Vec<(u8, u8)> {
    let mut shares = Vec::new();
    let mut xes = HashMap::new();

    for _ in 0..shares_num {
       
        //generate x and check for uniqeuness
        let mut point_x = GF256::from(rng.gen_range(0, 255));
        let mut counter = 0;
        loop {
            if xes.contains_key(&point_x.0) {
                if counter > 5 {
                    panic!("Could not generate unique x values");
                }
                point_x = GF256::from(rng.gen_range(0, 255));
                counter+=1;
                continue;
            } else {
                xes.insert(point_x.0, true);
                break
            }
        }

        let mut point_y = gf::GF(0);
        for i in 0..polynomial.len() {
            point_y += GF256::from(polynomial[i]) * point_x.pow(polynomial.len() - 1 - i);
        }
        shares.push((point_x.0, point_y.0));
    }
    shares
}

fn lagrange_interpolation(shares: &Vec<(u8, u8)>) -> u8 {
    let mut term = gf::GF(0);

    for i in 0..shares.len() {
        let mut numerator = gf::GF(1);
        let mut denominator = gf::GF(1);
        for j in 0..shares.len() {
            if i == j {
                continue;
            }
            //we evaulate it in the point 0
            numerator *= gf::GF(0) - gf::GF(shares[j].0);
            denominator *= gf::GF(shares[i].0) - gf::GF(shares[j].0);
        }
        term += gf::GF(shares[i].1) * numerator * denominator.inv();
    }
    term.0
}

//implement tests for the generate_polynomial function
#[cfg(test)]
mod tests {
    use super::*;

    struct MockRandom {
        start: u8,
    }

    impl Random for MockRandom {
        fn gen_range(&mut self, _low: u8, _high: u8) -> u8 {
            self.start+=1;
            self.start
        }
    }

    struct MockRandomFixed {
        value: u8,
    }

    impl Random for MockRandomFixed {
        fn gen_range(&mut self, _low: u8, _high: u8) -> u8 {        
            self.value
        }
    }

    #[test]
    fn test_generate_polynomial() {
        let degree = 3;
        let secret = 15;
        let mut mock_rng = MockRandom { start: 5 };
        //5x^3 + 5x^2 + 5x + 15
        let expected_polynomial = vec![6, 7, 8, 15];
        let polynomial = generate_polynomial(&mut mock_rng, degree, secret);
        assert_eq!(polynomial, expected_polynomial);

        let degree = 0;
        let secret = 15;
        let mut mock_rng = MockRandom { start: 5 };
        //15
        let expected_polynomail = vec![15];
        let polynomial = generate_polynomial(&mut mock_rng, degree, secret);
        assert_eq!(polynomial, expected_polynomail);
    }

    #[test]
    fn test_calculate_shares() {
        //5x^3 + 6x^2 + 7x + 15
        let polynomial = vec![5, 6, 7, 15];
        let shares_num = 4;
        let mut mock_rng = MockRandom { start: 5 };
        let shares = calculate_shares(&mut mock_rng, &polynomial, shares_num);
        assert_eq!(shares.len(), shares_num as usize);
    }

    #[test]
    #[should_panic]
    fn test_calculate_shares_panic() {
        //5x^3 + 6x^2 + 7x + 15
        let polynomial = vec![5, 6, 7, 15];
        let shares_num = 4;
        let mut mock_rng = MockRandomFixed { value: 5 };
        calculate_shares(&mut mock_rng, &polynomial, shares_num);
    }

    #[test]
    fn test_lagrange_interpolation() {
        //5x^3 + 6x^2 + 7x + 15
        let polynomial = vec![5, 6, 7, 15];
        let shares_num = 4;
        let mut mock_rng = MockRandom { start: 5 };
        let shares = calculate_shares(&mut mock_rng, &polynomial, shares_num);
        let secret = lagrange_interpolation(&shares);
        assert_eq!(secret, 15);

        let polynomial = vec![3,2,5,8,255];
        let shares_num = 5;
        let mut mock_rng = MockRandom { start: 5 };
        let shares = calculate_shares(&mut mock_rng, &polynomial, shares_num);
        let secret = lagrange_interpolation(&shares);
        assert_eq!(secret, 255);
        
        let polynomial = vec![3,2,5,8,255];
        let shares_num = 10;
        let mut mock_rng = MockRandom { start: 5 };
        let shares = calculate_shares(&mut mock_rng, &polynomial, shares_num);
        let secret = lagrange_interpolation(&shares);
        assert_eq!(secret, 255);

        let polynomial = vec![3,2,5,8,255];
        let shares_num = 4;
        let mut mock_rng = MockRandom { start: 5 };
        let shares = calculate_shares(&mut mock_rng, &polynomial, shares_num);
        let secret = lagrange_interpolation(&shares);
        assert_ne!(secret, 255);
    }

    #[test]
    fn test_sss_and_recover() {
        let expected_secret = "HELLO WORLD";
        let threshold = 3;

        let mut shares = sss(expected_secret, threshold, 5);
        let recover_secret = recover(&mut shares);
        assert_eq!(expected_secret, recover_secret);

        //remove 2 shares from the list, still should work
        let mut new_shares: Vec<(u8, Vec<(u8, u8)>)> = shares.into_iter().map(|mut s| {
            s.1.pop();
            s.1.pop();
            s
        }).collect();
     
        let recover_secret = recover(&mut new_shares);
        assert_eq!(expected_secret, recover_secret);

    }

    #[test]
    #[should_panic]
    fn test_sss_and_recover_not_enough_shares() {
        let expected_secret = "HELLO WORLD";
        let threshold = 3;

        let mut shares = sss(expected_secret, threshold, 2);
        recover(&mut shares);
    }

    #[test]
    #[should_panic]
    fn test_sss_and_recover_not_enough_shares_2() {
        let expected_secret = "HELLO WORLD";
        let threshold = 3;

        let shares = sss(expected_secret, threshold, 4);
        let mut new_shares: Vec<(u8, Vec<(u8, u8)>)> = shares.into_iter().map(|mut s| {
            s.1.pop();
            s.1.pop();
            s
        }).collect();

        recover(&mut new_shares);
    }
}
