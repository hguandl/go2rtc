# Marlboze

Native LAN input with HEVC main-stream video and PCMA/8000/mono audio.
No external SDK or transcoding is required. Use WebRTC with an HEVC-capable browser.

## Configuration

```yaml
streams:
  camera1: "marlboze://DEMO-123456-TEST:example-password@192.0.2.10?mac=02-00-00-00-00-01&stream=1"
  camera2: "marlboze://DEMO-654321-TEST:example-password@192.0.2.11?mac=02-00-00-00-00-02"
```

Use the device UID and password; percent-encode special characters in userinfo.
`mac` is required and accepts colon or hyphen notation.
`stream` defaults to `0` (substream); use `1` for the main stream.

## Connection timing

Wake and discovery start together. Wake packets repeat every 250 ms until
discovery succeeds or times out; each phase finishes immediately on success.

| Phase | Timeout or retry |
| --- | --- |
| Discovery | 15 s; requests every 500 ms |
| Wake during discovery | One packet every 250 ms |
| Login response | 5 s |
| Media probing | 15 s |
| Next frame | 10 s |
| Unrecovered packet gap | 3 s |
| Command ACK | Every 1 s; at most 4 sends including the first |

Wake retries do not extend discovery's deadline. Connections are on demand;
go2rtc handles sharing and reconnection. Wake reliability varies by device.

## Logging

Connection failures produce a warning. Enable stage timings and discovery
counters with:

```yaml
log:
  marlboze: debug
```

Timing fields are in milliseconds. No passwords, UID values or raw packets are
logged. Omit the override for normal operation.

## Validation

RTSP decoding and browser WebRTC playback were verified on one camera.
Other models are untested. Run the small, synthetic offline tests with:

```sh
go test ./pkg/marlboze ./internal/marlboze
```
