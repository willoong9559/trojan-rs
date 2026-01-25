use h2::Ping;
use tracing::{warn, debug};

use super::{PING_INTERVAL_SECS, PING_TIMEOUT_SECS, MAX_MISSED_PINGS};

pub(crate) struct H2Heartbeat {
    ping_pong: Option<h2::PingPong>,
    state: HeartbeatState,
    missed_pings: u32,
    timer: tokio::time::Interval,
}

enum HeartbeatState {
    Idle,
    WaitingPong(std::time::Instant),
}

impl H2Heartbeat {
    pub fn new(ping_pong: Option<h2::PingPong>) -> Self {
        Self {
            ping_pong,
            state: HeartbeatState::Idle,
            missed_pings: 0,
            timer: tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS)),
        }
    }

    pub fn on_activity(&mut self) {
        self.missed_pings = 0;
    }

    pub async fn poll(&mut self) -> Result<(), &'static str> {
        let waiting_pong = matches!(self.state, HeartbeatState::WaitingPong(_));
        
        if waiting_pong {
            if let Some(ref mut pp) = self.ping_pong {
                tokio::select! {
                    _ = self.timer.tick() => {
                        self.handle_tick()
                    }
                    result = futures_util::future::poll_fn(|cx| pp.poll_pong(cx)) => {
                        self.state = HeartbeatState::Idle;
                        self.missed_pings = 0;
                        match result {
                            Ok(_) => {
                                debug!("Received HTTP/2 PONG response");
                                Ok(())
                            }
                            Err(e) => {
                                warn!(error = %e, "HTTP/2 PONG receive error");
                                Err("PONG error")
                            }
                        }
                    }
                }
            } else {
                self.timer.tick().await;
                self.handle_tick()
            }
        } else {
            self.timer.tick().await;
            self.handle_tick()
        }
    }

    fn handle_tick(&mut self) -> Result<(), &'static str> {
        let Some(ref mut pp) = self.ping_pong else {
            return Ok(());
        };

        match &self.state {
            HeartbeatState::Idle => {
                if let Err(e) = pp.send_ping(Ping::opaque()) {
                    warn!(error = %e, "Failed to send HTTP/2 PING");
                } else {
                    self.state = HeartbeatState::WaitingPong(std::time::Instant::now());
                    debug!("Sent HTTP/2 PING frame");
                }
            }
            HeartbeatState::WaitingPong(sent_time) => {
                if sent_time.elapsed().as_secs() >= PING_TIMEOUT_SECS {
                    self.missed_pings += 1;
                    warn!(
                        missed_pings = self.missed_pings,
                        max_missed = MAX_MISSED_PINGS,
                        "HTTP/2 PING timeout"
                    );
                    if self.missed_pings >= MAX_MISSED_PINGS {
                        return Err("heartbeat timeout");
                    }
                    self.state = HeartbeatState::Idle;
                }
            }
        }
        Ok(())
    }

    async fn poll_pong(&mut self) -> Option<Result<h2::Pong, h2::Error>> {
        if !matches!(self.state, HeartbeatState::WaitingPong(_)) {
            return std::future::pending().await;
        }
        if let Some(ref mut pp) = self.ping_pong {
            Some(futures_util::future::poll_fn(|cx| pp.poll_pong(cx)).await)
        } else {
            std::future::pending().await
        }
    }
}

