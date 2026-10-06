# Release checklist

1. Copy `experiments/esp32_multidevice_D0_D5/` into the root of `L-PoPI-Revised-Implementation`.
2. Run `python3 experiments/esp32_multidevice_D0_D5/analysis/analyze_multidevice.py` and confirm all assertions pass.
3. Run all six `sha256sum -c` checks from the README.
4. Confirm acquisition commit `8670f38` is reachable on GitHub. If it exists only locally, push it before publication.
5. Commit the experiment directory without altering raw capture files.
6. Create an immutable GitHub tag/release, preferably `r1-multidevice-validation-2026-10-06` (or tag the final reproducibility commit and note that acquisition firmware was `8670f38`).
7. Optionally archive the release in Zenodo and use the resulting DOI in the final manuscript Data Availability Statement.
8. Only after the public release URL/DOI exists, replace the repository placeholder in the manuscript and reviewer response.

Suggested local commands after copying this directory into the repository:

```bash
cd ~/L-PoPI-Revised-Implementation
python3 experiments/esp32_multidevice_D0_D5/analysis/analyze_multidevice.py

git add experiments/esp32_multidevice_D0_D5
git commit -m "Add six-device ESP32 SRAM-PUF reproducibility dataset"
git push

git tag -a r1-multidevice-validation-2026-10-06 -m "L-PoPI D0-D5 multi-device validation"
git push origin r1-multidevice-validation-2026-10-06
```
