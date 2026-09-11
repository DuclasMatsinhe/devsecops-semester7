# Semester 7 — Continuous Security Validation Pipeline

## Project

Implementation of an integrated **DevSecOps Continuous Security Validation Pipeline for Cloud-Native Applications**.

The project integrates automated security validation into the CI/CD lifecycle using multiple security scanners and a custom **Security Validation Engine**. The engine normalizes findings from different security tools, evaluates their severity according to a defined security policy, and produces an explicit **security-gate decision** before the Docker build stage.

The goal is to support continuous, automated security validation and prevent builds from progressing when blocking security findings are detected.

---

## Architecture

Developer  
↓  
GitHub Repository  
↓  
GitHub Actions CI/CD  
↓  
Application Tests  
↓  
SAST + SCA + Secret Scanning  
↓  
Security Validation Engine  
↓  
Security Policy Evaluation  
↓  
Security Gate  
↓  
Docker Build  
↓  
Test Deployment

### Security Validation Flow

```text
Semgrep ────────┐
                │
pip-audit ──────┼──→ SecurityFinding
                │          │
Gitleaks ───────┘          ↓
                   SecurityValidationEngine
                            │
                            ↓
                    Severity Evaluation
                            │
                            ↓
                     Security Policy
                            │
                    ┌───────┴───────┐
                    ↓               ↓
                 PASSED           FAILED
                    │               │
                    ↓               ↓
              Docker Build      Pipeline Stops
