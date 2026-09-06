// rustmath — the Rust analog of prototype/corpus/src/mathlib.c for the A/B parity corpus.
//
// Same small call graph (gcd / fib / factorial / sum_to under main) so the harness has
// ground-truth function names to look for, plus one trait-object dispatch (a vtable, like the
// C++ `shapes` sample) so the Rust flavour of indirect calls is represented. The leaves are
// `#[inline(never)]` so they survive as real functions at opt-level=2; names are mangled
// (`_ZN8rustmath3gcd…`) and GayHydra's Rust demangler is expected to recover `rustmath::gcd`.
//
// Build (see ../build.sh): rustc --edition 2021 -C opt-level={0,2} -g -o … rustmath.rs

use std::env;

#[inline(never)]
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[inline(never)]
fn fib(n: u32) -> u64 {
    if n < 2 {
        return n as u64;
    }
    fib(n - 1) + fib(n - 2)
}

#[inline(never)]
fn factorial(n: u32) -> u64 {
    let mut r: u64 = 1;
    for i in 2..=n {
        r = r.wrapping_mul(i as u64);
    }
    r
}

#[inline(never)]
fn sum_to(n: u32) -> u64 {
    let mut s: u64 = 0;
    for i in 1..=n {
        s += i as u64;
    }
    s
}

trait Shape {
    fn area(&self) -> f64;
}

struct Circle(f64);
struct Square(f64);

impl Shape for Circle {
    #[inline(never)]
    fn area(&self) -> f64 {
        3.14159265 * self.0 * self.0
    }
}

impl Shape for Square {
    #[inline(never)]
    fn area(&self) -> f64 {
        self.0 * self.0
    }
}

#[inline(never)]
fn total_area(shapes: &[Box<dyn Shape>]) -> f64 {
    shapes.iter().map(|s| s.area()).sum()
}

fn main() {
    let n: u32 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    println!("gcd({},48)={}", n, gcd(n as u64, 48));
    println!("fib({})={}", n, fib(n));
    println!("fact({})={}", n, factorial(n));
    println!("sum({})={}", n, sum_to(n));
    let shapes: Vec<Box<dyn Shape>> = vec![Box::new(Circle(2.0)), Box::new(Square(3.0))];
    println!("total={:.3}", total_area(&shapes));
}
