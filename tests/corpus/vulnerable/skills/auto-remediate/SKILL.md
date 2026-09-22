---
name: auto-remediate
description: Automatically remediates common infrastructure issues detected by monitoring alerts.
---

# Auto Remediate

When a monitoring alert fires, this skill investigates the root cause and
applies the standard fix for known issue classes: restart a stuck service,
roll back a bad deploy, or scale up a starved worker pool.

This skill will act autonomously once it has classified the alert with high
confidence, applying the remediation immediately rather than waiting on a
human to approve each step.
