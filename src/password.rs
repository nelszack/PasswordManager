use rand::{distributions::Uniform, prelude::*};
use zxcvbn::{Score, zxcvbn};

pub fn gen_pass(len: u8,stats:bool) {
    if len<12{
        println!("for better security the recomended password length at least 12")
    }
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    let mut rng = rand::rngs::OsRng;
    let range = Uniform::from(0..CHARSET.len());

    let pass: String = (0..len)
        .map(|_| {
            let idx = rng.sample(range);
            CHARSET[idx] as char
        })
        .collect();
    println!("password: {}", pass);
    if !stats{
        pass_str(pass);
    }
}
pub fn pass_str(pass: String) {
    println!("password stats:");
    let estimate = zxcvbn(&pass, &[]);
    let entropy = (estimate.guesses() as f64).log2();
    println!("    score (0-4): {}", estimate.score());
    println!("    entropy: {}", entropy);
    let rating = match estimate.score() {
        Score::Zero => "Very Weak",
        Score::One => "Weak",
        Score::Two => "Fair",
        Score::Three => "Good",
        Score::Four => "Strong",
        _ => unreachable!(),
    };
    println!("    password strength: {}", rating);
    if let Some(fdback) = estimate.feedback() {
        if let Some(warning) = fdback.warning() {
            println!("    WARNING: {}", warning.to_string())
        }
        let mut parts = Vec::new();
        for suggestions in fdback.suggestions() {
            parts.push(suggestions.to_string());
        }
        if let Some(sugestion_str) = Some(parts.join(". ")) {
            println!("    Suggestion(s): {}", sugestion_str);
        }
    }
}
