use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use pnet_datalink::{self, Channel as PnetChannel, Config};
use sondare_datalink::Iface;
use crate::{EngineError, rate::RateLimiter};

/// Parameters for a sweep run.
pub struct SweepConfig {
    /// Max packets per second to transmit.
    pub pps: u32,
    /// How long to keep the receive window open after the last probe is sent.
    pub recv_grace: Duration,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self { pps: 1000, recv_grace: Duration::from_millis(500) }
    }
}

/// Run a stateless L2 sweep.
///
/// - `targets`: iterator of items to probe
/// - `build_frame`: turns a target into a raw Ethernet frame (uses codec)
/// - `parse_frame`: inspects each received frame; returns `Some(R)` to collect a result
/// - Returns all collected results after the receive window closes.
pub fn sweep<T, R, I, B, P>(
    iface: &Iface,
    targets: I,
    build_frame: B,
    parse_frame: P,
    cfg: SweepConfig,
) -> Result<Vec<R>, EngineError>
where
    T: Send + 'static,
    R: Send + 'static,
    I: IntoIterator<Item = T>,
    B: Fn(T) -> Option<Vec<u8>> + Send + 'static,
    P: Fn(&[u8]) -> Option<R> + Send + Sync + 'static,
{
    let channel_cfg = Config {
        read_timeout: Some(Duration::from_millis(10)),
        ..Config::default()
    };
    let (tx, rx) = match pnet_datalink::channel(&iface.inner, channel_cfg) {
        Ok(PnetChannel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(EngineError::Channel("unexpected channel type".into())),
        Err(e) => return Err(EngineError::Channel(e.to_string())),
    };

    let results: Arc<Mutex<Vec<R>>> = Arc::new(Mutex::new(Vec::new()));
    let results_rx = Arc::clone(&results);
    let parse_frame = Arc::new(parse_frame);

    // Signal: TX sets this once it finishes + grace period starts
    let deadline: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let deadline_rx = Arc::clone(&deadline);

    // RX thread
    let rx_handle = std::thread::spawn(move || {
        let mut rx = rx;
        loop {
            // Check if TX declared a deadline and it has passed
            if let Some(dl) = *deadline_rx.lock().unwrap() {
                if Instant::now() >= dl {
                    break;
                }
            }
            match rx.next() {
                Ok(frame) => {
                    if let Some(r) = parse_frame(frame) {
                        results_rx.lock().unwrap().push(r);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });

    // TX: send probes on the current thread
    let mut tx = tx;
    let mut rl = RateLimiter::new(cfg.pps, cfg.pps.min(256));
    for target in targets {
        if let Some(frame) = build_frame(target) {
            rl.take();
            let _ = tx.send_to(&frame, None);
        }
    }

    // Announce deadline to RX thread
    *deadline.lock().unwrap() = Some(Instant::now() + cfg.recv_grace);

    rx_handle.join().ok();

    // RX thread has joined; we are the sole Arc owner.
    Ok(Arc::into_inner(results)
        .expect("exclusive after join")
        .into_inner()
        .expect("mutex not poisoned"))
}
