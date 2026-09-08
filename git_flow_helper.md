# Git Branch Strategy

| Branch / Component | Purpose | Lifetime | Who Uses It | Merge / Deployment Rule |
|---|---|---|---|---|
| `main` | Production-ready code | Permanent | Everyone | Must always be deployable |
| `feature/*` | New feature or development work | Short-lived | Developers | PR → `main` |
| `fix/*` | Normal bug fixes | Short-lived | Developers | PR → `main` |
| `hotfix/*` | Critical production fixes | Very short | Developers / DevOps | PR → `main` + immediate production release |
| `release/*` | Optional release stabilization | Days | Release team | PR → `main`; use only when needed |
| `tag` e.g. `v2.4.0` | Immutable production version | Permanent | CI/CD | Created from `main` during release |



# Git Production Flow

## Normal Feature Flow

`feature/*` → `Pull Request` → `Code Review` → `CI/CD Checks` → `main` → `Staging` → `Production` → `Tag`

## Bug Fix Flow

`fix/*` → `Pull Request` → `Code Review` → `CI/CD Checks` → `main` → `Staging` → `Production` → `Tag`

## Critical Production Fix Flow

`hotfix/*` → `Pull Request` → `Code Review` → `CI/CD Checks` → `main` → `Production` → `Tag`

## Optional Release Flow

`feature/*` → `release/*` → `QA/Staging` → `main` → `Production` → `Tag`

## Complete Flow

```text
Developer
    ↓
feature/* or fix/*
    ↓
Pull Request
    ↓
Code Review
    ↓
CI/CD Checks
    ↓
main
    ↓
Staging
    ↓
QA / Approval
    ↓
Production
    ↓
Tag (v1.0.0)
