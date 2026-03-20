# Adversarial Defense & Anti-Spoofing Strategy

> Parametric insurance platforms pay out automatically when a user is physically present in a declared extreme-condition zone. This creates a direct financial attack surface: fake the location, collect the payout. This document details the architecture designed to close that gap — without punishing genuine users, without requiring expensive infrastructure, and without assuming attackers are unsophisticated.

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Why Naive Defenses Fail](#why-naive-defenses-fail)
3. [Architecture Overview](#architecture-overview)
4. [The Differentiation](#1-the-differentiation)
5. [The Data — Layer by Layer](#2-the-data)
6. [Scoring Logic](#scoring-logic)
7. [Event-Type Awareness](#event-type-awareness)
8. [The UX Balance](#3-the-ux-balance)
9. [Game Theory](#game-theory)
10. [Failure Analysis](#failure-analysis)
11. [Why This Works](#why-this-works)

---

## Threat Model

### Who the attacker is

A coordinated group of approximately 500 users — in this case, delivery workers — organising via a private Telegram group. They are not sophisticated state actors. They are opportunists with access to consumer-grade GPS spoofing tools, a shared coordination channel, and a financial incentive.

### What they are doing

- Installing a mock location application (e.g., Fake GPS GO, GPS Joystick) that overrides the OS location provider
- Pre-recording or downloading a route that passes through the declared trigger zone
- Replaying the route at a realistic speed (5–20 km/h) with minor randomisation to avoid obvious pattern detection
- Triggering claims simultaneously within a coordinated burst window communicated via Telegram
- Remaining physically at home throughout the entire process

### What makes this attack dangerous

The attack is dangerous not because it is technically sophisticated, but because it is **operationally scalable**. A single person sharing a working spoof APK and a pre-recorded route file in a Telegram group can arm 500 participants in under an hour. Each individual claim looks plausible. The damage is in the volume.

### What the attacker cannot easily fake

Physics. A phone sitting on a table at home does not vibrate like a phone being carried by a person. It does not see the same cell towers as the disaster zone. Its GPS accuracy does not oscillate the way real outdoor signals do in adverse weather. And critically — 500 phones all sitting at home look statistically identical to each other. 500 phones genuinely scattered across a disaster zone do not.

---

## Why Naive Defenses Fail

| Defense | Why it is insufficient |
|---|---|
| GPS coordinate validation | Mock location apps override the OS location API at the system level. The app receives legitimate-looking coordinates with valid accuracy metadata. No coordinate check detects this. |
| Movement and trajectory checks | Route replay tools simulate realistic motion at realistic speeds. Adding jitter to the route is a trivially automated one-line script change. |
| Device integrity checks (SafetyNet / Play Integrity) | Approximately 30% of gig workers in tier-2 and tier-3 cities use custom firmware, rooted devices, or budget phones with modified ROMs. Mass-flagging on integrity checks destroys legitimate UX. |
| Single behavioral heuristics | Any single-signal rule becomes public knowledge within the Telegram group within hours of deployment and is patched by the syndicate before the next payout window. |
| Checking GPS against weather API | Confirms the zone is active — does not confirm the user is in it. Confirms the attack is viable, not that it is happening. |

The fundamental failure in all of the above is that they **evaluate signals in isolation**. A coordinated attack that fails any single check just updates the shared script. A system that requires an attacker to simultaneously defeat independent physical, network, and population-level signals — with different update cycles and different evasion costs — is far more durable.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│           LAYER 0 — Secure Event Snapshot                       │
│              On-device · at trigger moment · offline-safe       │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────┐ │
│  │  GPS + Timestamp  │  │  Sensor Metadata  │  │Server Nonce │ │
│  │  at trigger time  │  │  motion, accuracy │  │ anti-replay │ │
│  └───────────────────┘  └───────────────────┘  └─────────────┘ │
│                                                                 │
│        Cryptographically signed · submitted on reconnect        │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│           LAYER 1 — Device Physics Fingerprint                  │
│              On-device · <1s · zero network cost                │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────┐ │
│  │   Accelerometer   │  │  Battery Temp      │  │ GPS Accuracy│ │
│  │ GPS vel vs motion │  │  Delta (8 min)     │  │  Variance   │ │
│  └───────────────────┘  └───────────────────┘  └─────────────┘ │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│           LAYER 2 — Network Topology Coherence                  │
│              Backend async · <3s · lightweight DB lookup        │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────┐ │
│  │  Cell Tower Scan  │  │  WiFi BSSID Scan  │  │     IP      │ │
│  │ Towers vs zone    │  │  Zone vs home net │  │ Geolocation │ │
│  └───────────────────┘  └───────────────────┘  └─────────────┘ │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  ★  LAYER 3 — Swarm Pattern Detection  (WOW Differentiator)     │
│              Backend · <5s async · event-stream across sessions │
│                                                                 │
│  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────┐ │
│  │  Claim Velocity   │  │ Device Model Mix  │  │   Sensor    │ │
│  │ Spike vs baseline │  │ Entropy check     │  │ Fingerprint │ │
│  └───────────────────┘  └───────────────────┘  └─────────────┘ │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             ┌────────────┐ ┌──────────┐ ┌───────────┐
             │   AUTO     │ │  SOFT    │ │  FRAUD    │
             │  APPROVE   │ │ CHALLENGE│ │   HOLD    │
             └────────────┘ └──────────┘ └───────────┘
```

---

## 1. The Differentiation

- GPS coordinates alone are trivially faked using consumer spoofing apps. This system validates **physical environment coherence** — cross-checking signals that a location spoofing app cannot patch without significantly increasing attack cost and technical complexity.
- Detection runs across **4 layers**: temporal integrity (Layer 0), on-device physics (Layer 1), network topology (Layer 2), and population-level swarm analysis (Layer 3). Each layer is independent. Defeating one does not defeat the others.
- Each layer is **event-type aware** — signal weights adjust dynamically based on the declared disaster type. A flood victim who is stationary and sheltered is not penalised for looking like someone who is not moving. The system knows what genuine presence looks like for each event type.
- No external infrastructure, no telecom provider APIs, no satellite services, no invasive biometric tracking. Built entirely on standard Android and iOS permissions available to any published application.
- The system's most powerful property is asymmetric: **the larger the coordinated attack, the more detectable it becomes**. Individual spoofing is harder to catch than mass spoofing. This inverts the attacker's incentive structure.

**Key Insight:** Real disasters produce high-entropy device populations — different towers, different networks, different motion profiles, different device models, spread across a physical zone. Coordinated fraud from home produces low-entropy clusters — statistically identical sensor profiles, same device models, same spoofing app artifacts, submitted in a tight burst window. The system exploits this asymmetry at the population level using no ML training and no complex infrastructure.

---

## 2. The Data

### Layer 0 — Secure Event Snapshot
*On-device capture at the moment of trigger. Fully offline-capable.*

Layer 0 is not a fraud detector. It is a **temporal integrity guarantee**. Its job is to prove that the claim payload was generated at the moment of the event — not assembled retroactively after the attacker confirmed the zone was active and the payout was available.

| Component | What it captures | Why it matters |
|---|---|---|
| GPS coordinates + timestamp | Location and exact time at trigger moment | Binds the claim to a specific real-time context. Prevents post-event fabrication. |
| Sensor metadata | Motion state, GPS accuracy radius, signal pattern at capture time | Provides the ground truth that Layers 1 and 2 score against |
| Server-issued nonce | One-time token pre-fetched from backend at zone entry or app launch | Cryptographically unique per session. Prevents replay — a valid snapshot cannot be resubmitted across multiple claim windows. |
| OS mock location flag | Android `IS_MOCK` provider field, captured at snapshot time | Passive signal. A `true` value is not an automatic reject but is a weighted risk input. |

The entire payload is signed on-device using a device-bound private key. The backend verifies the signature on receipt. If connectivity is unavailable at the trigger moment, the signed payload is stored locally and submitted when the network recovers. No re-capture required. No user action required.

> **Important scope note:** A sophisticated attacker running a full spoof stack at the exact trigger moment can still generate a validly-signed fake snapshot. The signature proves the payload was not tampered with in transit — it does not prove the sensor readings inside it were genuine. That is the job of Layers 1–3.

---

### Layer 1 — Device Physics Fingerprint
*On-device computation. Result available in under 1 second. Zero network cost.*

This layer asks: does the device's physical state match the conditions of the declared event zone? Three signals are cross-checked. Signals are included or excluded based on event type — see [Event-Type Awareness](#event-type-awareness).

| Signal | Source | Time window | Genuine pattern | Spoofed pattern |
|---|---|---|---|---|
| Accelerometer coherence | `SensorManager` TYPE_ACCELEROMETER | 15-second rolling average | GPS velocity and accelerometer-derived motion within 25% of each other | GPS shows 10–20 km/h movement; accelerometer shows near-resting ±0.2g flatline |
| Battery temperature delta | `BatteryManager.EXTRA_TEMPERATURE` | Two readings, 8 minutes apart | Temperature shifts ≥0.8°C reflecting outdoor thermal exposure | Temperature remains flat ±0.3°C — consistent with a phone at rest indoors |
| GPS accuracy variance | `Location.getAccuracy()` from GPS provider | 10 readings over 2 minutes | Accuracy radius oscillates between ~8m and ~45m as signal bounces | Fixed at 4–6m with near-zero variance — a spoofing app artifact |

**Output:** A Physics Confidence Score (PCS) from 0.0 to 1.0. The denominator adjusts to the number of signals available on the device. A phone with missing or unavailable sensors is scored out of fewer total points — not penalised for missing hardware.

**Scoring thresholds:**

```
PCS >= 0.70        →  Pass. Proceed to Layer 2 at standard weight.
PCS  0.40 – 0.69   →  Borderline. Layer 2 runs with elevated NCS weight.
PCS <  0.40        →  Flag. Layer 2 runs. Layer 3 queued regardless of Layer 2 result.
```

---

### Layer 2 — Network Topology Coherence
*Backend async validation. Completes in under 3 seconds. No telecom provider API required.*

This layer asks: does the device's ambient network environment match the declared zone? A spoofer at home sees their home city's cell towers and their home router. These cannot be faked by a GPS spoofing app — they reflect the device's actual physical location.

| Signal | Source | Expected: genuine user | Expected: spoofer |
|---|---|---|---|
| Cell tower scan | `TelephonyManager` Cell ID + LAC list | At least 1 visible tower matches the zone's known tower profile | Zero tower overlap — all visible towers belong to a different area |
| WiFi BSSID scan | `WifiManager.getScanResults()` ACCESS_WIFI_STATE | BSSIDs consistent with commercial or street-level networks near the zone | Home router BSSID visible — a residential profile inconsistent with the declared zone |
| IP geolocation gap | API request source IP, resolved to city level at backend | IP city matches or is adjacent to the GPS-claimed city | IP city diverges from GPS city — supplementary risk signal, not a standalone block |

**How zone profiles are built:** The tower and BSSID lookup tables are populated from prior verified claims submitted in each zone. No telecom API required — genuine users who submitted valid claims in past events left a tower and BSSID fingerprint. For new zones with no prior claim history, public telecom coverage maps pre-populate the table, and Layer 1 is automatically weighted higher in the composite score.

**Output:** A Network Coherence Score (NCS) from 0.0 to 1.0.

**Composite Confidence Score (CCS):**

```
CCS = (PCS × 0.45) + (NCS × 0.55)

CCS >= 0.65        →  Auto-approve path
CCS  0.40 – 0.64   →  Soft challenge path
CCS <  0.40        →  Fraud hold path (Layer 3 always runs)
```

NCS is weighted slightly higher because network topology reflects physical location more directly than device physics, which can vary legitimately with event conditions.

---

### Layer 3 — Swarm Pattern Detection
*Backend event stream analysis. Async, under 5 seconds. Operates across all concurrent sessions.*

**This is the WOW differentiator.**

This layer does not evaluate any individual user. It evaluates the **population of claimants as a collective system** during a spike window. Individual signal profiles are difficult to distinguish from genuine users under some conditions — but the population-level statistical fingerprint of coordinated fraud is unmistakable.

**Trigger condition:** Layer 3 activates when the claim rate for a zone exceeds 4× the calibrated historical baseline within a 90-second window. Below this threshold Layer 3 is dormant — no unnecessary processing overhead.

**Three checks run in parallel once triggered:**

**1. Claim velocity spike analysis**

The baseline claim rate per zone is derived from historical event data. A 4× spike in 90 seconds is the activation threshold. The spike alone is not a fraud flag — real disasters produce genuine spikes. It is the signal that checks 2 and 3 should run.

**2. Device model entropy check**

For all claimants in the spike window, compute the Shannon entropy of device models and OS versions:

```
H = -Σ p(x) × log₂(p(x))
```

In a genuine event, delivery workers across a city carry a wide variety of devices. Entropy is high. In a coordinated Telegram-organised attack, the group shared a working spoof APK confirmed on specific device models. The cluster of identical model + OS + app version combinations collapses entropy.

```
Flag condition: top-3 device model cluster > 35% of spike-window claimants
```

**3. Sensor fingerprint similarity clustering**

Layer 1 produces a signal vector per device: [accelerometer variance, battery delta, GPS accuracy std dev]. These vectors are compared pairwise across all spike-window claimants using cosine similarity.

In a genuine event: people are distributed across a physical zone doing different things. Pairwise similarity is low — vectors are diverse. In a coordinated fraud burst: all phones are stationary at home running the same spoofing app with near-zero motion and artificially stable GPS accuracy. Pairwise similarity collapses to near-identical vectors.

No ML training required. This is a dot product against a rolling population vector — a single lightweight aggregation query on the active session stream.

```
Flag condition: mean pairwise cosine similarity > 0.82 across spike-window claimants
```

**What happens when Layer 3 flags a swarm:**

All claims in the spike window move to a **15-minute async hold** — not rejected.

```
During hold:
  L1 >= 0.65 AND L2 >= 0.65  →  Released automatically
  L1 passes, L2 borderline   →  Soft challenge path
  L1 borderline, L2 passes   →  Soft challenge path
  Both below threshold        →  24-hour human review queue
  Both failed + swarm flag    →  Fraud hold
```

---

## Scoring Logic

Full decision path from claim initiation to verdict:

```
Claim initiated
      │
      ▼
Layer 0: Signature valid? Nonce unused?
      ├── No  →  Reject (tampered payload or replay attack)
      └── Yes
            │
            ▼
      Layer 1: Compute PCS
            ├── PCS >= 0.70  →  Layer 2 at standard weight
            ├── PCS 0.40–0.69  →  Layer 2 at elevated NCS weight
            └── PCS < 0.40  →  Layer 2 + queue Layer 3 regardless
                        │
                        ▼
               Layer 2: Compute NCS → derive CCS
                        │
                        ├── CCS >= 0.65
                        │       └── Layer 3 swarm flag active?
                        │             ├── No   →  AUTO-APPROVE
                        │             └── Yes  →  15-min hold
                        │                           └── L1+L2 both pass?
                        │                                 ├── Yes  →  Release
                        │                                 └── No   →  Review queue
                        │
                        ├── CCS 0.40–0.64  →  SOFT CHALLENGE
                        │       ├── Pass  →  Approve
                        │       └── Fail  →  24-hr review queue
                        │
                        └── CCS < 0.40  →  Layer 3
                                    ├── Swarm confirmed  →  FRAUD HOLD
                                    └── No swarm  →  24-hr review queue
```

---

## Event-Type Awareness

Layer 1 signal weights are adjusted based on the declared event type. This prevents the system from penalising genuine users whose physical state is consistent with the disaster — not with normal activity.

| Event type | Accelerometer | Battery temp delta | GPS accuracy variance | Primary trust layer |
|---|---|---|---|---|
| Storm transit | Active — motion expected | Active — thermal exposure expected | Active | Layer 1 + Layer 2 |
| Flood (stranded) | Disabled — stillness is genuine | Disabled — sheltered phone stays dry | Active | Layer 2 carries full weight |
| Heatwave | Disabled — stillness is genuine | Active — warming expected | Active | Layer 1 partial + Layer 2 |
| Cold snap | Disabled — stillness is genuine | Active — cooling expected | Active | Layer 1 partial + Layer 2 |

When Layer 1 signals are disabled for an event type, the PCS denominator shrinks accordingly and the score normalises to the active signals only. A flood claimant is not penalised for having a smaller signal set.

For flood events, Layer 2 (network topology) carries the primary verification weight. A person stranded in a flood zone still sees the towers and WiFi networks of that zone regardless of whether they are moving or stationary.

---

## 3. The UX Balance

### Normal user flow — zero friction

PCS high, NCS high, no swarm flag active.

```
User opens app during declared event
        │
        Layer 0 snapshot captured silently in background
        │
        Layers 1 and 2 run in background (<4 seconds total)
        │
        CCS >= 0.65, no swarm flag
        │
        "Claim verified. Payout processing."
```

The user sees one screen. No prompts, no challenges, no delays beyond normal processing time.

---

### Suspicious case flow — minimal friction

CCS is borderline (0.40–0.64). Common legitimate causes include: sheltering inside a concrete building with degraded GPS, older device with inconsistent sensor readings, first-time claimant with no prior profile.

```
CCS falls in borderline range
        │
        Single prompt displayed:
        "We could not automatically verify your location.
         Please take a quick 10-second photo of your surroundings."
        │
        ├── Photo captured
        │       Validated for:
        │         - EXIF timestamp within ±30 seconds of request time
        │         - Gyroscope data confirms phone was physically moved during capture
        │       │
        │       ├── Both pass  →  Claim approved immediately
        │       └── Either fails  →  24-hour human review queue
        │
        └── User skips  →  24-hour human review queue
```

The photo is not analysed for visual content. No image recognition, no computer vision pipeline, no content stored beyond the validation window. Only metadata is checked — timestamp and gyroscope movement. This respects user privacy while confirming physical presence at the moment of capture.

---

### Edge case handling

**Poor connectivity during the event**

Layer 0 handles this by design. The signed snapshot — including cell tower scan and WiFi BSSID list — is captured and stored on-device at the trigger moment. When connectivity resumes, the full payload is submitted. The backend validates the signature, checks the nonce, and processes all layers against the stored snapshot data. No re-capture, no re-verification, no user action required.

**Old or low-end device with missing sensors**

Missing signals are excluded from scoring, not treated as failed signals. The PCS denominator adjusts to the count of sensors present and returning valid readings within the expected range. Only active, valid signals contribute to the score.

**Legitimate but unusual motion profile (vehicle passenger)**

Vehicle motion produces a distinct accelerometer signature: high velocity, sustained vibration, periodic braking and acceleration patterns. This is distinguishable from both pedestrian motion and the stationary-at-home profile. The system maintains calibrated profiles for common legitimate conditions built from the historical claim corpus. A vehicle passenger in a disaster zone matches the vehicle-passenger profile.

**First-time claimant with no history**

No prior claim history means no personal baseline. The system does not penalise this. Layers 1 and 2 operate on current session signals only. Layer 3 operates on population signals, not individual history. A first-time claimant is evaluated purely on the physics and network coherence of their current submission.

**False positive — genuine user receives a fraud hold**

Any user who receives a fraud hold sees the following in-app:

> "Your claim is under additional review. This is not a rejection. You will receive a decision within 24 hours. If you believe this is in error, tap below to submit a brief appeal."

The appeal flow accepts a short text description and an optional photo. Human reviewers process appeals within the stated SLA. All cleared appeals result in full payout with no account penalty. The user's profile is updated to reflect the verified legitimate claim, improving their scoring baseline for future events.

---

## Game Theory

**Increasing attacker effort compounds with scale**

Defeating GPS validation requires only a consumer spoofing app — low effort, widely available. Defeating GPS validation plus accelerometer coherence requires hooking into a second OS API, which most consumer spoof tools do not do. Defeating GPS plus accelerometer plus battery temperature plus network topology requires a full device emulation stack. This exists for rooted Android devices with the Xposed framework, but it is not mass-distributable via a Telegram APK link to 500 gig workers. Each additional layer compounds the technical setup required per device.

**Profitability shrinks as group size increases**

In a normal fraud system, more participants means more payouts — coordination amplifies returns. In this system, the swarm detection layer means that expected value per participant *decreases* as group size increases. A solo attacker with a polished spoof stack might pass Layers 1 and 2. A 500-person coordinated burst produces a population-level signal the system is specifically calibrated to catch. The attacker's most profitable strategy — small, dispersed groups with diverse device setups and staggered timing — is also their most operationally expensive strategy, limiting per-event payout to a level that may not justify the coordination cost.

**Coordination becomes evidence**

The tight burst timing, the device model clustering, the sensor similarity — all are artifacts of Telegram-organised synchronisation. The very operational pattern that makes mass coordination efficient for attackers is the signal that exposes them. This is a structural property, not a heuristic that can be patched with a script update.

---

## Failure Analysis

**Weakness 1: Rooted device with full sensor API spoofing**

A technically skilled attacker using a rooted Android device with the Xposed framework can hook into every sensor API — GPS, accelerometer, battery manager, WiFi scan — and return fabricated values.

Why it is acceptable: This requires individual device rooting — a per-device manual process that is not achievable via a Telegram APK distribution to 500 participants. The OS mock location flag captured in Layer 0 is a soft risk signal for this configuration. More importantly, Layer 3 still catches the population-level artifact: even if individual signals are polished, a 500-person burst with coordinated timing and identical device configurations collapses entropy in the swarm checks.

---

**Weakness 2: Attacker who physically travels to the zone**

A bad actor who actually travels to the declared disaster zone has legitimate physical presence. All layers pass. The claim is approved.

Why it is acceptable: This is correct behaviour, not a failure. The cost of physically entering a genuine extreme weather event substantially offsets or eliminates the financial gain from a fraudulent payout. Parametric insurance payouts are calibrated against the risk of being in the zone. Requiring physical presence to collect a payout is the baseline requirement the system exists to enforce.

---

**Weakness 3: Cold-start zone with no tower or BSSID history**

A trigger zone that has never had a prior valid claim has no tower or BSSID profile to match against. Layer 2's network checks return neutral — not negative — scores.

Why it is acceptable: Two mitigations are in place. Public telecom coverage map data pre-populates approximate zone tower profiles before any claims arrive. When Layer 2 lookup data is sparse, the system automatically increases the weight of Layer 1 physics signals. The verdict path is more conservative in cold-start zones — borderline CCS scores route to soft challenge rather than auto-approve — but genuine users with strong physics signals are not blocked.

---

## Why This Works

- **Feasible on any device:** All signals use permissions available to published applications. No root access, no external APIs, no hardware beyond accelerometer and GPS — present on every smartphone manufactured in the last decade.

- **Scalable at low cost:** Layer 1 is fully on-device — zero backend compute per claim for physics scoring. Layer 2 is a key-value lookup against a pre-built table — sub-millisecond per query. Layer 3 is a single rolling aggregation over the active session stream — one query across all concurrent users, not one query per user.

- **Resistant to adaptation:** Multiple independent signal types across different layers with different update cycles. Patching the spoof toolkit to defeat Layer 1 does not affect Layer 2 or Layer 3. Each layer requires a different technical approach to defeat, and the fixes are not composable — no single change addresses all layers simultaneously.

- **Protects genuine users under real disaster conditions:** Event-type awareness ensures that signals most likely to produce false positives in genuine extreme weather are disabled when the event type makes them unreliable. The system always has a human fallback for borderline cases, and every false positive has a clear, low-friction appeal path with a guaranteed SLA.

- **Inverts the attacker's incentive at scale:** The larger and more coordinated the attack, the more visible it becomes. This is the structural property that makes the system durable against the specific threat profile — a large, organised, financially motivated group exploiting a parametric trigger at scale.
