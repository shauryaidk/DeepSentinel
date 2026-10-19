import numpy as np


def detect_beacon(
    timestamps: list[float] | np.ndarray,
    bin_size_sec: float = 1.0,
    snr_threshold: float = 10.0,   # v3: fitted on the 1M-sample training split (was 4.0)
    max_jitter_cv: float = 0.5,    # v3: fitted on the 1M-sample training split (was 0.35)
    min_packets: int = 8,
) -> dict:
    """
    Detects rigid and jittered periodic C2 beaconing.
    """
    ts = np.sort(np.array(timestamps, dtype=float))
    n = len(ts)
    if n < min_packets:
        return {"alert": False, "confidence": 0.0, "reason": "Insufficient packets"}

    iats = np.diff(ts)
    valid_iats = iats[iats > 0.05]
    if len(valid_iats) < 4:
        return {"alert": False, "confidence": 0.0, "reason": "Bursty traffic"}

    mean_iat = np.mean(valid_iats)
    std_iat = np.std(valid_iats)
    cv = std_iat / (mean_iat + 1e-9)
    t_min, t_max = ts[0], ts[-1]
    duration = t_max - t_min
    if duration < 10.0:
        return {"alert": False, "confidence": 0.0, "reason": "Window too short"}

    bins = np.arange(t_min, t_max + bin_size_sec, bin_size_sec)
    signal, _ = np.histogram(ts, bins=bins)
    signal = signal - np.mean(signal)
    fft_vals = np.fft.fft(signal)
    magnitudes = np.abs(fft_vals)
    freqs = np.fft.fftfreq(len(signal), d=bin_size_sec)

    pos_mask = freqs > 0
    pos_freqs = freqs[pos_mask]
    pos_mags = magnitudes[pos_mask]

    fft_snr = 0.0
    detected_period = 0.0
    if len(pos_mags) > 0:
        peak_idx = np.argmax(pos_mags)
        peak_freq = pos_freqs[peak_idx]
        mean_mag = np.mean(pos_mags)
        fft_snr = float(pos_mags[peak_idx] / (mean_mag + 1e-9))
        detected_period = float(1.0 / peak_freq) if peak_freq > 0 else 0.0

    is_periodic = fft_snr > snr_threshold
    is_low_jitter = (cv < max_jitter_cv) and (mean_iat > 1.0)

    alert = bool(is_periodic or is_low_jitter)
    confidence = min(1.0, max(fft_snr / 10.0, 1.0 - cv))

    return {
        "alert": alert,
        "threat_type": "botnet_c2_beacon",
        "confidence": round(confidence, 3),
        "estimated_interval_sec": round(
            detected_period if is_periodic else mean_iat, 2
        ),
        "fft_snr": round(fft_snr, 2),
        "iat_cv": round(float(cv), 3),
    }
