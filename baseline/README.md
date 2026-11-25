# Original CS24 Baseline - Intentionally Insecure Reference

This folder contains selected source files copied from the original CS24 ZIP supplied by the student. It is retained only for static review and optional container-image scanning.

**WARNING: DO NOT RUN THESE SERVICES OR THEIR ORIGINAL COMPOSE FILE.** The original code intentionally contains weak demo credentials, a Base64 username token, unauthenticated AI and log routes, raw prompt/response logging, Flask debug mode, and direct service port exposure. The original Compose file is deliberately not included here.

The `scripts/build_baseline_images.py` script only builds the original service images. It does not start them. The images can then be scanned by `scripts/scan_local_images.py` using the same Trivy scanner settings as the hardened 2.0 images.
