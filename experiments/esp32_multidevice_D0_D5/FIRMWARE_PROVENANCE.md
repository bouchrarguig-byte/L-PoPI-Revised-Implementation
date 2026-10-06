# Firmware provenance

The collector metadata for all six devices records acquisition commit:

`8670f38`

This experiment must be released only after that commit (or an immutable tag that contains exactly the same acquisition firmware and collector behavior) is publicly reachable in the parent repository.

Recommended immutable release tag:

`r1-multidevice-validation-2026-10-06`

Before publication, verify locally from the repository used for acquisition:

```bash
git show --stat 8670f38
git status --short
git push origin 8670f38:refs/heads/r1-multidevice-validation
git tag -a r1-multidevice-validation-2026-10-06 8670f38 -m "Frozen L-PoPI six-device SRAM-PUF validation"
git push origin r1-multidevice-validation-2026-10-06
```

If the experiment directory is committed after `8670f38`, tag the final reproducibility commit instead, but retain `8670f38` in the metadata as the acquisition-firmware provenance.
