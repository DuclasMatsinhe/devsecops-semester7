# Semester 7 — Continuous Security Validation Pipeline

## Project
Implementation of a Continuous Security Validation Pipeline for Cloud-Based Applications.

## Semester 7 baseline architecture

Developer
→ GitHub Repository
→ GitHub Actions CI/CD
→ SAST + SCA + Secret Scanning
→ Security Validation
→ Security Gate
→ Docker Build
→ Test Deployment

## Initial technology stack

- Python + Flask
- GitHub
- GitHub Actions
- Semgrep (SAST)
- pip-audit (SCA)
- Gitleaks (secret scanning)
- Docker

## Current implementation status

1. Flask application scaffold
2. Automated application test
3. CI workflow
4. SAST stage
5. SCA stage
6. Secret scanning stage
7. Docker build stage

## Next milestones

- Verify the pipeline with a clean commit.
- Confirm each scanner produces usable output.
- Implement an explicit security-policy/gate layer.
- Add controlled test vulnerabilities.
- Add test deployment.
