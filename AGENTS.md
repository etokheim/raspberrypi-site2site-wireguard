# AI Harness Instructions

This file captures durable, non-obvious decisions for AI agents working in this repository.

## Core Principle: Unattended Setup

For setup or reconfiguration flows, use a two-phase approach:

1. **Planning/Input phase**  
   Collect all required user answers first (interfaces, LAN CIDR, WireGuard config path, firewall choice, optional features, etc.).
2. **Execution phase**  
   Only after inputs are complete, run long or disruptive actions (installing packages, changing system config, restarting services).

Do not start dependency installation early while still asking configuration questions.

## Why This Matters

- Package install and network changes can take significant time.
- The user should be able to answer prompts once and then leave the process unattended.
- Mid-install prompts increase failure risk and operator frustration on remote systems.

## Agent Behavior Requirements

- Prefer "gather once, execute once" for interactive setup UX.
- If information is missing, ask before triggering long-running operations.
- Keep setup steps idempotent and resilient across reboot/power loss.

## Critical Operational Principles

These principles must be preserved by any change to setup/cleanup/management scripts:

### SSH-Safety During Install

Remote installation over SSH must remain possible. Avoid actions that can drop the operator's SSH connection:

- Never unconditionally `ip addr flush` an interface without first verifying it is not the SSH-bearing path.
- Detect the SSH-bearing interface (via `SSH_CONNECTION` / `who am i`) and warn loudly before reassigning its address.
- Prefer to skip a step when the desired state already matches current state (idempotent no-op).
- When changing iptables, ensure ACCEPT rules for SSH precede any DROP/REJECT rules at all times.

### Reboot Survivability

Configuration must survive reboot and power loss without manual intervention:

- Persist all iptables/nat rules to disk after applying them, regardless of optional features.
- Do not couple non-tunnel-related rules (like WAN MASQUERADE) to `wg-quick` PostUp/PostDown.
- Use systemd ordering (`After`, `Wants`, optional `BindsTo`) to make services start only when their network prerequisites are ready.
- Back up replaced system files only the first time (do not overwrite the backup on re-runs).

### Re-Run Idempotency

Re-running setup on a configured Pi must reconfigure cleanly and fix prior reboot/persistence issues:

- Detect existing systemd units, drop-ins, and config files; replace only when content differs.
- Clean up rules and units tied to a previous interface when the user reassigns interfaces.
- Avoid destructive restarts (e.g., `wg-quick down`) when nothing changed.
- The `--start` recovery path should also create/update missing systemd units, not just start them.

### Disconnect-Safe Execution

The execution phase must finish on its own even if the operator's terminal goes away (SSH drop, Pi Connect WebRTC failure, serial hang-up, laptop closed). Half-applied state on a remote Pi can be unrecoverable.

- After the input phase, the script must detach from its controlling terminal: ignore `SIGHUP`, close stdin, and route stdout/stderr to the persistent log file.
- Live progress on the operator's TTY may be provided by a side-channel `tail -f` that dies harmlessly when the TTY goes away.
- Detect remote-management daemons (Raspberry Pi Connect, etc.) before the execution phase and warn explicitly when WireGuard `AllowedIPs` includes a default route (`0.0.0.0/0`, `::/0`, or `0.0.0.0/1` + `128.0.0.0/1`) - that single setting is the most common way a remote-managed Pi loses its management plane after `wg-quick up`.
- Never add a prompt after the input phase. Any new question must move into the input-collection block.

## Living Decisions (Automatic Maintenance)

When a user prompt introduces a new durable project decision:

1. Update this `AGENTS.md` with that decision.
2. Update relevant `.cursor/rules/*.mdc` so the behavior is enforced in future sessions.
3. Keep additions concise and action-oriented.

Treat this as required maintenance, not optional documentation.
