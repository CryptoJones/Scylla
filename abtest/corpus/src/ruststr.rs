// ruststr — the Rust analog of prototype/corpus/src/strutil.c for the A/B parity corpus: string
// handling (reverse, vowel count, palindrome test, word histogram via a BTreeMap), a Result-
// returning parser (so `?`-style Err paths are present), and one trait-object dispatch. A second,
// differently-shaped Rust program next to rustmath.
//
// Build (see ../build.sh): rustc --edition 2021 -C opt-level={0,1,2,3,s,z} -C panic={unwind,abort} … ruststr.rs

use std::collections::BTreeMap;
use std::env;

#[inline(never)]
fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}

#[inline(never)]
fn count_vowels(s: &str) -> usize {
    s.chars()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count()
}

#[inline(never)]
fn is_palindrome(s: &str) -> bool {
    let t: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    t == reverse(&t)
}

#[inline(never)]
fn word_histogram(s: &str) -> BTreeMap<String, usize> {
    let mut h = BTreeMap::new();
    for w in s.split_whitespace() {
        *h.entry(w.to_ascii_lowercase()).or_insert(0) += 1;
    }
    h
}

#[inline(never)]
fn parse_repeat(arg: Option<&str>) -> Result<usize, String> {
    match arg {
        None => Ok(1),
        Some(a) => a
            .parse::<usize>()
            .map_err(|e| format!("bad repeat {a:?}: {e}"))
            .and_then(|n| if n > 0 && n <= 8 { Ok(n) } else { Err("repeat out of range".into()) }),
    }
}

trait Scorer {
    fn score(&self, s: &str) -> usize;
}

struct LenScorer;
struct VowelScorer(usize);

impl Scorer for LenScorer {
    #[inline(never)]
    fn score(&self, s: &str) -> usize {
        s.len()
    }
}

impl Scorer for VowelScorer {
    #[inline(never)]
    fn score(&self, s: &str) -> usize {
        self.0 * count_vowels(s)
    }
}

#[inline(never)]
fn best(scorers: &[Box<dyn Scorer>], s: &str) -> usize {
    scorers.iter().map(|sc| sc.score(s)).max().unwrap_or(0)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let s = if args.is_empty() {
        "reverse engineering never odd or even".to_string()
    } else {
        args.join(" ")
    };
    let n = match parse_repeat(env::var("REPEAT").ok().as_deref()) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    };
    let s = s.repeat(n);
    println!("rev={:?}", reverse(&s));
    println!("vowels={} palindrome={}", count_vowels(&s), is_palindrome(&s));
    for (k, v) in word_histogram(&s) {
        println!("{k}={v}");
    }
    let scorers: Vec<Box<dyn Scorer>> = vec![Box::new(LenScorer), Box::new(VowelScorer(3))];
    println!("best={}", best(&scorers, &s));
}
