use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct EngineMetrics {
    active_connections: AtomicI64,
    processed_queries: AtomicU64,
    authenticated_tenant_sessions: AtomicU64,
    breaker_trips: AtomicU64,
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    established_sessions: AtomicU64,
    failed_sessions: AtomicU64,
    blocked_violations: AtomicU64,
    policy_admission_checks: AtomicU64,
    policy_admission_allowed: AtomicU64,
    policy_admission_denied: AtomicU64,
    policy_admission_session_revocations: AtomicU64,
    client_bytes: AtomicU64,
    database_bytes: AtomicU64,
    session_duration_micros: AtomicU64,
    completed_sessions: AtomicU64,
    query_latency_count: AtomicU64,
    query_latency_sum_micros: AtomicU64,
    query_latency_le_1ms: AtomicU64,
    query_latency_le_5ms: AtomicU64,
    query_latency_le_10ms: AtomicU64,
    query_latency_le_50ms: AtomicU64,
    query_latency_le_100ms: AtomicU64,
    query_latency_le_500ms: AtomicU64,
    query_latency_le_1s: AtomicU64,
}

struct QueryStart {
    started: Instant,
    simple_query: bool,
}

#[derive(Default)]
pub struct QueryLatencyTracker {
    starts: Mutex<VecDeque<QueryStart>>,
}

impl QueryLatencyTracker {
    pub fn start(&self, simple_query: bool) {
        if let Ok(mut starts) = self.starts.lock() {
            if starts.len() >= 1024 {
                starts.pop_front();
            }
            starts.push_back(QueryStart {
                started: Instant::now(),
                simple_query,
            });
        }
    }

    pub fn finish_extended(&self) {
        self.finish_if(|query| !query.simple_query);
    }

    pub fn finish_simple(&self) {
        self.finish_if(|query| query.simple_query);
    }

    fn finish_if(&self, should_finish: impl FnOnce(&QueryStart) -> bool) {
        let started = self.starts.lock().ok().and_then(|mut starts| {
            if starts.front().is_some_and(should_finish) {
                starts.pop_front().map(|query| query.started)
            } else {
                None
            }
        });
        if let Some(started) = started {
            let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
            global().observe_query_latency(elapsed);
        }
    }
}

static METRICS: OnceLock<Arc<EngineMetrics>> = OnceLock::new();

pub fn global() -> Arc<EngineMetrics> {
    METRICS
        .get_or_init(|| Arc::new(EngineMetrics::default()))
        .clone()
}

impl EngineMetrics {
    pub fn connection_accepted(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn connection_rejected(&self) {
        self.rejected_connections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn session_started(&self, authenticated_tenant: bool) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.established_sessions.fetch_add(1, Ordering::Relaxed);
        if authenticated_tenant {
            self.authenticated_tenant_sessions
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn query_processed(&self) {
        self.processed_queries.fetch_add(1, Ordering::Relaxed);
    }
    pub fn breaker_tripped(&self) {
        self.breaker_trips.fetch_add(1, Ordering::Relaxed);
    }
    pub fn processed_queries(&self) -> u64 {
        self.processed_queries.load(Ordering::Relaxed)
    }
    pub fn authenticated_tenant_sessions(&self) -> u64 {
        self.authenticated_tenant_sessions.load(Ordering::Relaxed)
    }
    pub fn blocked_violations(&self) -> u64 {
        self.blocked_violations.load(Ordering::Relaxed)
    }
    pub fn breaker_has_tripped(&self) -> bool {
        self.breaker_trips.load(Ordering::Relaxed) > 0
    }
    pub fn breaker_trips(&self) -> u64 {
        self.breaker_trips.load(Ordering::Relaxed)
    }
    pub fn session_failed(&self) {
        self.failed_sessions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn violation_blocked(&self) {
        self.blocked_violations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn policy_admission_checked(&self) {
        self.policy_admission_checks.fetch_add(1, Ordering::Relaxed);
    }
    pub fn policy_admission_allowed(&self) {
        self.policy_admission_allowed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn policy_admission_denied(&self) {
        self.policy_admission_denied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn policy_admission_session_revoked(&self) {
        self.policy_admission_session_revocations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn observe_query_latency(&self, elapsed_micros: u64) {
        self.query_latency_count.fetch_add(1, Ordering::Relaxed);
        self.query_latency_sum_micros
            .fetch_add(elapsed_micros, Ordering::Relaxed);
        if elapsed_micros <= 1_000 {
            self.query_latency_le_1ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 5_000 {
            self.query_latency_le_5ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 10_000 {
            self.query_latency_le_10ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 50_000 {
            self.query_latency_le_50ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 100_000 {
            self.query_latency_le_100ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 500_000 {
            self.query_latency_le_500ms.fetch_add(1, Ordering::Relaxed);
        } else if elapsed_micros <= 1_000_000 {
            self.query_latency_le_1s.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn session_finished(&self, client_bytes: u64, database_bytes: u64, duration_micros: u64) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.client_bytes.fetch_add(client_bytes, Ordering::Relaxed);
        self.database_bytes
            .fetch_add(database_bytes, Ordering::Relaxed);
        self.session_duration_micros
            .fetch_add(duration_micros, Ordering::Relaxed);
        self.completed_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let completed = self.completed_sessions.load(Ordering::Relaxed);
        let duration = self.session_duration_micros.load(Ordering::Relaxed);
        let mut output = format!(concat!(
            "# HELP proxima_engine_processed_queries_total PostgreSQL simple and extended Execute query messages observed.\n",
            "# TYPE proxima_engine_processed_queries_total counter\n",
            "proxima_engine_processed_queries_total {}\n",
            "# HELP proxima_engine_authenticated_tenant_sessions_total Tenant-token authenticated sessions established.\n",
            "# TYPE proxima_engine_authenticated_tenant_sessions_total counter\n",
            "proxima_engine_authenticated_tenant_sessions_total {}\n",
            "# HELP proxima_engine_security_breaker_trips_total Number of peer-scoped security breaker trips.\n",
            "# TYPE proxima_engine_security_breaker_trips_total counter\n",
            "proxima_engine_security_breaker_trips_total {}\n",
            "# HELP proxima_engine_active_connections Active PostgreSQL sessions.\n",
            "# TYPE proxima_engine_active_connections gauge\n",
            "proxima_engine_active_connections {}\n",
            "# HELP proxima_engine_connections_accepted Total TCP connections accepted.\n",
            "# TYPE proxima_engine_connections_accepted counter\n",
            "proxima_engine_connections_accepted_total {}\n",
            "# HELP proxima_engine_connections_rejected Total connections rejected by capacity or breaker policy.\n",
            "# TYPE proxima_engine_connections_rejected counter\n",
            "proxima_engine_connections_rejected_total {}\n",
            "# HELP proxima_engine_sessions_established Total PostgreSQL sessions established.\n",
            "# TYPE proxima_engine_sessions_established counter\n",
            "proxima_engine_sessions_established_total {}\n",
            "# HELP proxima_engine_sessions_failed Total failed session handshakes.\n",
            "# TYPE proxima_engine_sessions_failed counter\n",
            "proxima_engine_sessions_failed_total {}\n",
            "# HELP proxima_engine_security_violations_blocked Total protocol or tenant-security violations blocked.\n",
            "# TYPE proxima_engine_security_violations_blocked counter\n",
            "proxima_engine_security_violations_blocked_total {}\n",
            "# HELP proxima_engine_policy_admission_checks_total Signed PostgreSQL policy admission checks performed.\n",
            "# TYPE proxima_engine_policy_admission_checks_total counter\n",
            "proxima_engine_policy_admission_checks_total {}\n",
            "# HELP proxima_engine_policy_admission_allowed_total Policy admission decisions that allowed tenant sessions.\n",
            "# TYPE proxima_engine_policy_admission_allowed_total counter\n",
            "proxima_engine_policy_admission_allowed_total {}\n",
            "# HELP proxima_engine_policy_admission_denied_total Policy admission decisions that denied tenant sessions.\n",
            "# TYPE proxima_engine_policy_admission_denied_total counter\n",
            "proxima_engine_policy_admission_denied_total {}\n",
            "# HELP proxima_engine_policy_admission_session_revocations_total Active sessions closed after a policy recheck denied access.\n",
            "# TYPE proxima_engine_policy_admission_session_revocations_total counter\n",
            "proxima_engine_policy_admission_session_revocations_total {}\n",
            "# HELP proxima_engine_client_bytes_total Bytes copied from clients to PostgreSQL.\n",
            "# TYPE proxima_engine_client_bytes_total counter\n",
            "proxima_engine_client_bytes_total {}\n",
            "# HELP proxima_engine_database_bytes_total Bytes copied from PostgreSQL to clients.\n",
            "# TYPE proxima_engine_database_bytes_total counter\n",
            "proxima_engine_database_bytes_total {}\n",
            "# HELP proxima_engine_session_duration_seconds_total Cumulative duration of completed sessions.\n",
            "# TYPE proxima_engine_session_duration_seconds_total counter\n",
            "proxima_engine_session_duration_seconds_total {:.6}\n",
            "# HELP proxima_engine_sessions_completed Total completed PostgreSQL sessions.\n",
            "# TYPE proxima_engine_sessions_completed counter\n",
            "proxima_engine_sessions_completed_total {}\n"
        ),
            self.processed_queries.load(Ordering::Relaxed),
            self.authenticated_tenant_sessions.load(Ordering::Relaxed),
            self.breaker_trips.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
            self.accepted_connections.load(Ordering::Relaxed),
            self.rejected_connections.load(Ordering::Relaxed),
            self.established_sessions.load(Ordering::Relaxed),
            self.failed_sessions.load(Ordering::Relaxed),
            self.blocked_violations.load(Ordering::Relaxed),
            self.policy_admission_checks.load(Ordering::Relaxed),
            self.policy_admission_allowed.load(Ordering::Relaxed),
            self.policy_admission_denied.load(Ordering::Relaxed),
            self.policy_admission_session_revocations.load(Ordering::Relaxed),
            self.client_bytes.load(Ordering::Relaxed),
            self.database_bytes.load(Ordering::Relaxed),
            duration as f64 / 1_000_000.0,
            completed
        );
        output.push_str("# HELP proxima_engine_query_roundtrip_latency_seconds PostgreSQL request-to-completion latency observed by the proxy.\n");
        output.push_str("# TYPE proxima_engine_query_roundtrip_latency_seconds histogram\n");
        let buckets = [
            ("0.001", self.query_latency_le_1ms.load(Ordering::Relaxed)),
            ("0.005", self.query_latency_le_5ms.load(Ordering::Relaxed)),
            ("0.01", self.query_latency_le_10ms.load(Ordering::Relaxed)),
            ("0.05", self.query_latency_le_50ms.load(Ordering::Relaxed)),
            ("0.1", self.query_latency_le_100ms.load(Ordering::Relaxed)),
            ("0.5", self.query_latency_le_500ms.load(Ordering::Relaxed)),
            ("1", self.query_latency_le_1s.load(Ordering::Relaxed)),
        ];
        let mut cumulative = 0u64;
        for (bound, count) in buckets {
            cumulative = cumulative.saturating_add(count);
            output.push_str(&format!(
                "proxima_engine_query_roundtrip_latency_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        let count = self.query_latency_count.load(Ordering::Relaxed);
        output.push_str(&format!(
            "proxima_engine_query_roundtrip_latency_seconds_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        output.push_str(&format!(
            "proxima_engine_query_roundtrip_latency_seconds_sum {:.9}\n",
            self.query_latency_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
        ));
        output.push_str(&format!(
            "proxima_engine_query_roundtrip_latency_seconds_count {count}\n"
        ));
        output
    }
}

pub async fn serve(addr: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener).await
}

pub async fn serve_listener(listener: TcpListener) -> io::Result<()> {
    tracing::info!(addr = %listener.local_addr()?, "Proxima Prometheus metrics listener started");
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut request = [0u8; 2048];
            let size = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read(&mut request),
            )
            .await
            {
                Ok(Ok(size)) => size,
                _ => return,
            };
            let first_line = String::from_utf8_lossy(&request[..size]);
            let path = first_line.split_whitespace().nth(1).unwrap_or("/");
            let (status, content_type, body) = if path == "/metrics" {
                (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    global().render_prometheus(),
                )
            } else if path == "/health" || path == "/healthz" {
                ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string())
            } else {
                (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "not found\n".to_string(),
                )
            };
            let headers = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n", body.len());
            let _ = stream.write_all(headers.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metrics_exposition_is_prometheus_compatible_and_tracks_sessions() {
        let metrics = EngineMetrics::default();
        metrics.connection_accepted();
        metrics.policy_admission_checked();
        metrics.policy_admission_allowed();
        metrics.policy_admission_checked();
        metrics.policy_admission_denied();
        metrics.policy_admission_session_revoked();
        metrics.session_started(true);
        metrics.session_finished(100, 80, 2_500);
        metrics.observe_query_latency(500);
        metrics.observe_query_latency(50_000);
        let output = metrics.render_prometheus();
        assert!(output.contains("proxima_engine_active_connections 0\n"));
        assert!(output.contains("proxima_engine_connections_accepted_total 1\n"));
        assert!(output.contains("proxima_engine_client_bytes_total 100\n"));
        assert!(output.contains("proxima_engine_database_bytes_total 80\n"));
        assert!(output.contains("proxima_engine_session_duration_seconds_total 0.002500\n"));
        assert!(output.contains("proxima_engine_authenticated_tenant_sessions_total 1\n"));
        assert!(output.contains("proxima_engine_policy_admission_checks_total 2\\n"));
        assert!(output.contains("proxima_engine_policy_admission_allowed_total 1\\n"));
        assert!(output.contains("proxima_engine_policy_admission_denied_total 1\\n"));
        assert!(output.contains("proxima_engine_policy_admission_session_revocations_total 1\\n"));
        assert!(output
            .contains("proxima_engine_query_roundtrip_latency_seconds_bucket{le=\"0.001\"} 1\n"));
        assert!(output
            .contains("proxima_engine_query_roundtrip_latency_seconds_bucket{le=\"0.05\"} 2\n"));
        assert!(output.contains("proxima_engine_query_roundtrip_latency_seconds_count 2\n"));
    }
}
