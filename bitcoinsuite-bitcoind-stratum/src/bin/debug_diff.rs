use bitcoinsuite_bitcoind_stratum::{difficulty_to_target, network_target_to_difficulty};

fn main() {
    let target = difficulty_to_target(1.0).unwrap();
    println!("Target (hex): {}", hex::encode(&target));
    let diff = network_target_to_difficulty(&target).unwrap();
    println!("Network difficulty: {}", diff);
}
