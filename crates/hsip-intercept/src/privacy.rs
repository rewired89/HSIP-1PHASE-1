//! Privacy-enhancing features for the intercept system.

use rand::Rng;
use std::time::Duration;
use tracing::debug;

/// Add random timing jitter to mask user behavior patterns.
///
/// This helps prevent timing-based fingerprinting by adding a random delay
/// between event detection and overlay display.
///
/// # Default Range
/// 50ms - 500ms (configurable via InterceptConfig)
pub async fn add_timing_jitter() {
    add_timing_jitter_range(50, 500).await;
}

/// Add timing jitter with custom range.
pub async fn add_timing_jitter_range(min_ms: u64, max_ms: u64) {
    let jitter = rand::thread_rng().gen_range(min_ms..=max_ms);
    debug!("Adding timing jitter: {}ms", jitter);
    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

/// Normalize message send time to 5-minute windows.
///
/// This prevents precise timing correlation by rounding timestamps
/// to the nearest 5-minute interval.
pub fn normalize_timestamp(ts: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let minutes = ts.minute();
    let normalized_minutes = (minutes / 5) * 5;

    ts.with_minute(normalized_minutes)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap()
}

/// Pad message to fixed size buckets to hide actual message length.
///
/// Messages are padded to nearest bucket size (256, 512, 1024, 2048, 4096 bytes).
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    const BUCKETS: &[usize] = &[256, 512, 1024, 2048, 4096, 8192];

    let current_len = message.len();

    // Find the next bucket size
    let target_size = BUCKETS.iter()
        .find(|&&size| size >= current_len)
        .copied()
        .unwrap_or(current_len + 256); // If too large, add 256 bytes

    let mut padded = Vec::with_capacity(target_size);
    padded.extend_from_slice(message);

    // Pad with random bytes (more secure than zeros)
    let padding_len = target_size - current_len;
    let padding: Vec<u8> = (0..padding_len)
        .map(|_| rand::random::<u8>())
        .collect();
    padded.extend_from_slice(&padding);

    debug!("Padded message: {} -> {} bytes", current_len, target_size);
    padded
}

/// Strip EXIF metadata from images.
///
/// This removes potentially identifying information like:
/// - GPS coordinates
/// - Camera model
/// - Timestamps
/// - Software used
///
/// # Future Implementation
/// Requires image processing library (e.g., image-rs, kamadak-exif)
pub fn strip_image_metadata(image_data: &[u8]) -> Result<Vec<u8>, String> {
    // TODO: Implement EXIF stripping
    // For now, return original data
    warn!("Image metadata stripping not yet implemented");
    Ok(image_data.to_vec())
}

/// Generate cover traffic to mask messaging patterns.
///
/// Sends dummy packets at regular intervals to make it harder
/// to determine when real messages are being sent.
///
/// # Future Feature
/// This is planned for Phase 3 (Stable release).
pub async fn start_cover_traffic(intensity: CoverTrafficIntensity) {
    // TODO: Implement cover traffic generation
    warn!("Cover traffic not yet implemented");
}

/// Cover traffic intensity levels.
#[derive(Debug, Clone, Copy)]
pub enum CoverTrafficIntensity {
    /// Low: ~1 packet per minute
    Low,
    /// Medium: ~1 packet per 10 seconds
    Medium,
    /// High: ~1 packet per second
    High,
}

use tracing::warn;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_timestamp_normalization() {
        let ts = chrono::Utc::now()
            .with_minute(37)
            .unwrap()
            .with_second(42)
            .unwrap();

        let normalized = normalize_timestamp(ts);

        // Should round down to 35 minutes
        assert_eq!(normalized.minute(), 35);
        assert_eq!(normalized.second(), 0);
        assert_eq!(normalized.nanosecond(), 0);
    }

    #[test]
    fn test_message_padding() {
        // Small message should be padded to 256 bytes
        let message = b"Hello, HSIP!";
        let padded = pad_message(message);
        assert_eq!(padded.len(), 256);

        // 300-byte message should be padded to 512 bytes
        let large_message = vec![0u8; 300];
        let padded = pad_message(&large_message);
        assert_eq!(padded.len(), 512);
    }

    #[tokio::test]
    async fn test_timing_jitter() {
        use std::time::Instant;

        let start = Instant::now();
        add_timing_jitter_range(100, 200).await;
        let elapsed = start.elapsed();

        // Should take between 100-200ms
        assert!(elapsed.as_millis() >= 100);
        assert!(elapsed.as_millis() <= 250); // Allow some overhead
    }
}
