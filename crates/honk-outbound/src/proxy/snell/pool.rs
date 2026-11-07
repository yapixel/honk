use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::protocol::Snell;
use crate::proxy::AsyncReadWrite;

pub type PoolStream = Snell<Box<dyn AsyncReadWrite>>;

pub struct SnellPool {
    items: Mutex<Vec<(PoolStream, Instant)>>,
    retired: AtomicBool,
    max_size: usize,
    max_age: Duration,
}

impl std::fmt::Debug for SnellPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellPool")
            .field("idle_len", &self.idle_len())
            .field("retired", &self.retired.load(Ordering::Relaxed))
            .field("max_size", &self.max_size)
            .field("max_age", &self.max_age)
            .finish()
    }
}

impl SnellPool {
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            items: Mutex::new(Vec::new()),
            retired: AtomicBool::new(false),
            max_size,
            max_age,
        }
    }

    pub fn take_idle(&self) -> Option<PoolStream> {
        if self.retired.load(Ordering::Acquire) {
            return None;
        }
        let now = Instant::now();
        let mut items = self.items.lock();
        if self.retired.load(Ordering::Acquire) {
            return None;
        }
        while let Some((mut conn, expires_at)) = items.pop() {
            if now >= expires_at {
                continue;
            }
            if !conn.idle_conn_alive() {
                continue;
            }
            return Some(conn);
        }
        None
    }

    pub fn put(&self, conn: PoolStream) {
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        let mut items = self.items.lock();
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        if items.len() >= self.max_size {
            items.remove(0);
        }
        items.push((conn, Instant::now() + self.max_age));
    }

    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        let mut items = self.items.lock();
        items.clear();
    }

    pub fn reap_expired(&self) -> usize {
        let mut items = self.items.lock();
        let now = Instant::now();
        let before = items.len();
        items.retain(|(_, expires_at)| *expires_at > now);
        before - items.len()
    }

    pub fn idle_len(&self) -> usize {
        self.items.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn make_stream() -> (PoolStream, DuplexStream) {
        let (a, b) = tokio::io::duplex(1024);
        let boxed: Box<dyn AsyncReadWrite> = Box::new(a);
        (Snell::new(boxed, Arc::from(b"k".as_slice())), b)
    }

    #[tokio::test]
    async fn pool_lifo_order() {
        let pool = SnellPool::new(10, Duration::from_secs(60));
        let (s1, mut p1) = make_stream();
        let (s2, mut p2) = make_stream();

        pool.put(s1);
        pool.put(s2);
        assert_eq!(pool.idle_len(), 2);

        let mut popped1 = pool.take_idle().unwrap();
        popped1.write_all(b"first").await.unwrap();
        popped1.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n2 = p2.read(&mut buf).await.unwrap();
        assert!(n2 > 0, "most recently added stream comes back first (s2)");

        let mut popped2 = pool.take_idle().unwrap();
        popped2.write_all(b"second").await.unwrap();
        popped2.flush().await.unwrap();
        let n1 = p1.read(&mut buf).await.unwrap();
        assert!(n1 > 0, "older stream comes back second (s1)");

        assert!(pool.take_idle().is_none());
    }

    #[tokio::test]
    async fn pool_expiry_on_take_and_reap_expired() {
        let pool = SnellPool::new(10, Duration::from_millis(20));
        let (s1, _p1) = make_stream();
        let (s2, _p2) = make_stream();

        pool.put(s1);
        pool.put(s2);
        assert_eq!(pool.idle_len(), 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(pool.reap_expired(), 2);
        assert_eq!(pool.idle_len(), 0);

        let (s3, _p3) = make_stream();
        pool.put(s3);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pool.take_idle().is_none());
        assert_eq!(pool.idle_len(), 0);
    }

    #[tokio::test]
    async fn pool_retire_drops_idle_and_refuses_put() {
        let pool = SnellPool::new(10, Duration::from_secs(60));
        let (s1, _p1) = make_stream();
        pool.put(s1);
        assert_eq!(pool.idle_len(), 1);

        pool.retire();
        assert_eq!(pool.idle_len(), 0);
        assert!(pool.take_idle().is_none());

        let (s2, _p2) = make_stream();
        pool.put(s2);
        assert_eq!(pool.idle_len(), 0);
        assert!(pool.take_idle().is_none());
    }

    #[tokio::test]
    async fn pool_full_drops_oldest() {
        let pool = SnellPool::new(2, Duration::from_secs(60));
        let (s1, mut p1) = make_stream();
        let (s2, mut p2) = make_stream();
        let (s3, mut p3) = make_stream();

        pool.put(s1);
        pool.put(s2);
        pool.put(s3);
        assert_eq!(pool.idle_len(), 2);

        // s1 should have been dropped because the pool capacity was 2.
        let mut buf = [0u8; 64];
        let n1 = p1.read(&mut buf).await.unwrap();
        assert_eq!(n1, 0, "oldest stream s1 was dropped on full pool");

        let mut popped3 = pool.take_idle().unwrap();
        popped3.write_all(b"3").await.unwrap();
        popped3.flush().await.unwrap();
        let n3 = p3.read(&mut buf).await.unwrap();
        assert!(n3 > 0, "s3 was returned first");

        let mut popped2 = pool.take_idle().unwrap();
        popped2.write_all(b"2").await.unwrap();
        popped2.flush().await.unwrap();
        let n2 = p2.read(&mut buf).await.unwrap();
        assert!(n2 > 0, "s2 was returned second");

        assert!(pool.take_idle().is_none());
    }

    #[tokio::test]
    async fn pool_discards_dead_connection_on_take() {
        let pool = SnellPool::new(10, Duration::from_secs(60));
        let (s1, mut p1) = make_stream();
        let (s2, p2) = make_stream();

        pool.put(s1);
        pool.put(s2);

        drop(p2); // s2 is dead

        let mut popped = pool.take_idle().unwrap();
        popped.write_all(b"alive").await.unwrap();
        popped.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n1 = p1.read(&mut buf).await.unwrap();
        assert!(n1 > 0, "live stream s1 returned after dead s2 discarded");
        assert!(pool.take_idle().is_none());
    }
}
