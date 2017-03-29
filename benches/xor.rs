#![feature(test)]

extern crate rand;
extern crate test;

use rand::Rng;

#[bench]
fn xor(b: &mut test::Bencher) {
    let mut data = vec![0; 1024 * 1024 * 16];
    rand::weak_rng().fill_bytes(&mut data);

    let mut mask = [0, 0, 0, 0];
    rand::weak_rng().fill_bytes(&mut mask);

    b.iter(|| {
        for (byte, &mask) in data.iter_mut().zip(mask.iter().cycle()) {
            *byte ^= mask;
        }
    });
}