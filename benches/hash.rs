use std::fs;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let dir = std::env::temp_dir().join(format!("manitou-bench-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for i in 0..8 {
        fs::write(dir.join(format!("shard{i}.bin")), vec![i as u8; 8 * 1_048_576]).unwrap();
    }
    let t = Instant::now();
    let m = manitou::record(black_box(&dir), "bench/model").unwrap();
    println!("record 64 MiB ({} files): {:?}", m.files.len(), t.elapsed());
    let t = Instant::now();
    black_box(manitou::verify(&dir, &m));
    println!("verify: {:?}", t.elapsed());
    fs::remove_dir_all(&dir).ok();
}
