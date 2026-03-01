# Git Repository Policy - Documentation Organization

**Last Updated:** 2026  
**Status:** Active

## Overview

This document defines which documentation files and folders are tracked in the git repository and which are kept private/local only.

## Repository Structure

### Public Documentation (Tracked in Git)

The following documentation is **PUBLIC** and tracked in the git repository:

#### Core Technical Documentation (docs/ root)
All technical specifications and guides in the `docs/` root folder:
- Architecture & Security specs
- Deployment guides (public)
- Performance benchmarks
- Cryptography specifications
- Formal verification documents
- State machine specifications
- Testing plans
- Technical API documentation

**Total:** 39 files in `docs/` root

#### Research Documentation (docs/research/)
Academic papers, whitepapers, and formal security analysis:
- WHITEPAPER_DRAFT.md
- ACADEMIC_REVISION_SUMMARY.md
- B4AE_VS_E2EE_ARCHITECTURE.md
- HYBRID_COMPOSITION_RATIONALE.md
- HYBRID_MODEL_STRATEGY.md
- KEY_COMPROMISE_ANALYSIS.md
- MULTI_SESSION_SECURITY_ANALYSIS.md
- METADATA_LEAKAGE_ANALYSIS.md

**Total:** 8 files

#### Implementation Documentation (docs/implementation/)
SDK guides, platform documentation, and implementation notes:
- MOBILE_SDK_ENHANCED_GUIDE.md
- PLATFORM_SDK.md
- HSM_INTEGRATION_GUIDE.md
- ELARA_INTEGRATION.md
- ELARA_CRATES_IO_PUBLISH.md
- CRATES_IO_PUBLISH_PREP.md
- GATEWAY_PROXY.md
- PLUGIN_ARCHITECTURE.md
- ENTERPRISE_CONTROL_PLANE_DESIGN.md
- IMPLEMENTATION_SECURITY_NOTES.md
- ERROR_HANDLING_SECURITY.md

**Total:** 11 files

---

### CI/CD Configuration (Tracked in Git)

#### GitHub Actions (.github/)
**Reason:** Required for CI/CD pipelines, automated testing, and releases

Files included:
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/pages.yml
- .github/workflows/publish.yml
- .github/workflows/release.yml
- .github/dependabot.yml

**Total:** 6 files (CI/CD configuration)

**Note:** The `.github/` folder MUST be tracked in git for GitHub Actions to work.

---

### Private Documentation (NOT Tracked in Git)

The following documentation is **PRIVATE** and excluded from git repository:

#### Business Strategy (docs/business/)
**Reason:** Contains sensitive business information, partnerships, funding strategies

Files excluded:
- STRATEGIC_VISION.md
- PARTNER_PROGRAM.md
- PAID_SUPPORT_TIER.md
- OPEN_COLLECTIVE_APPLICATION.md
- OPEN_COLLECTIVE_SUBMISSION_CHECKLIST.md
- PILOT_OUTREACH_TEMPLATE.md
- WEBSITE_POSITIONING.md
- RELAY_NETWORK_PLANNING.md

**Total:** 8 files

#### Compliance & Certifications (docs/compliance/)
**Reason:** May contain sensitive audit information, government bid details, certification drafts

Files excluded:
- COMPLIANCE_CERTIFICATION_DRAFT.md
- COMPLIANCE_CERTIFICATION_PREP.md
- COMPLIANCE_MATRIX.md
- GOVERNMENT_BID_CHECKLIST.md
- EXTERNAL_AUDIT_CHECKLIST.md
- EXTERNAL_AUDIT_PREPARATION_PACK.md
- EXTERNAL_AUDIT_READINESS.md
- AUDIT_FEATURES_ANALYSIS.md
- AUDIT_IMPLEMENTATION_MISMATCHES.md
- AUDITOR_RFP_OUTREACH.md

**Total:** 10 files

#### Archive (docs/archive/)
**Reason:** Internal planning documents, old checklists, superseded specifications

Files excluded:
- V2_PLANNING.md (archived - v2.0 complete)
- NEXT_STEPS_IMPLEMENTATION.md (archived - v2.0 complete)
- RELEASE_CHECKLIST.md
- SDK_DISTRIBUTION_CHECKLIST.md
- WHITEPAPER_PUBLICATION_CHECKLIST.md
- CODEQL_LANGUAGES_FIX.md
- ENHANCED_STATE_MACHINE.md (superseded)
- DOS_MODEL_SECURITY_HARDENING.md (superseded)
- DOWNGRADE_PROTECTION_HARDENING.md (superseded)

**Total:** 9 files

#### Internal Process Documentation
**Reason:** Internal audit reports and process documentation

Files excluded:
- docs/P1_DOCUMENTATION_UPDATE_SUMMARY.md
- docs/P2_P3_DOCUMENTATION_UPDATE_SUMMARY.md
- docs/DOCUMENTATION_AUDIT_REPORT.md

**Total:** 3 files

#### Kiro IDE Specs (.kiro/)
**Reason:** Internal development specs, feature planning, and IDE configurations

Files excluded:
- .kiro/specs/b4ae-v2-research-grade-architecture/
- .kiro/specs/hybrid-double-ratchet/
- .kiro/specs/security-hardening-suite/
- .kiro/specs/timestamp-validation-fix/
- All .config.kiro files
- All internal spec files (requirements.md, design.md, tasks.md, bugfix.md)

**Total:** All files in .kiro/ folder

---

## Implementation

### .gitignore Configuration

The following entries are added to `.gitignore`:

```gitignore
# Kiro IDE - Internal specs and configurations
.kiro/

# Documentation - Exclude sensitive/private folders
docs/business/
docs/compliance/
docs/archive/

# Documentation - Exclude internal planning and audit prep
docs/P1_DOCUMENTATION_UPDATE_SUMMARY.md
docs/P2_P3_DOCUMENTATION_UPDATE_SUMMARY.md
docs/DOCUMENTATION_AUDIT_REPORT.md
```

### Removing Previously Committed Files

If sensitive files were previously committed to the repository, use the provided script:

```bash
# Run from repository root
bash remove_sensitive_docs.sh
```

This script:
1. Removes files from git tracking using `git rm --cached`
2. Keeps files on local disk
3. Requires manual commit and push

### Manual Removal (Alternative)

If you prefer manual removal:

```bash
# Remove .kiro folder (internal specs)
git rm -r --cached .kiro/

# Remove folders from git (keep locally)
git rm -r --cached docs/business/
git rm -r --cached docs/compliance/
git rm -r --cached docs/archive/

# Remove individual files
git rm --cached docs/P1_DOCUMENTATION_UPDATE_SUMMARY.md
git rm --cached docs/P2_P3_DOCUMENTATION_UPDATE_SUMMARY.md
git rm --cached docs/DOCUMENTATION_AUDIT_REPORT.md

# Commit changes
git commit -m "Remove sensitive documentation from repository"

# Push to remote
git push origin main
```

---

## Summary Statistics

| Category | Files | Status |
|----------|-------|--------|
| **Public (in git)** | 64 files | ✅ Tracked |
| - Core docs (root) | 39 files | ✅ Tracked |
| - Research | 8 files | ✅ Tracked |
| - Implementation | 11 files | ✅ Tracked |
| - CI/CD (.github/) | 6 files | ✅ Tracked |
| **Private (not in git)** | 30+ files | 🔒 Excluded |
| - Business | 8 files | 🔒 Excluded |
| - Compliance | 10 files | 🔒 Excluded |
| - Archive | 9 files | 🔒 Excluded |
| - Internal process | 3 files | 🔒 Excluded |
| - Kiro IDE specs | All .kiro/ | 🔒 Excluded |
| **Total** | 94+ files | - |

---

## Rationale

### Why Separate Public and Private?

1. **Security:** Business strategy and compliance documents may contain sensitive information
2. **Privacy:** Partnership and funding applications contain confidential details
3. **Professionalism:** Internal planning and audit reports are not relevant to external users
4. **Focus:** Public repository should focus on technical documentation useful to developers
5. **Compliance:** Some certification and audit documents should not be publicly disclosed

### What Belongs in Public Repository?

- Technical specifications and architecture
- Security analysis and threat models
- Deployment guides (general)
- Performance benchmarks
- Research papers and whitepapers
- SDK and implementation guides
- Testing plans and methodologies

### What Should Stay Private?

- Business development and strategy
- Partnership and funding applications
- Compliance certifications and audit prep
- Government bid documents
- Internal planning and checklists
- Process documentation and audit reports
- Internal development specs and feature planning (.kiro/)

---

## Maintenance

### Adding New Documentation

When creating new documentation, consider:

1. **Is it technical?** → Add to `docs/` root or appropriate subfolder (research/implementation)
2. **Is it business-related?** → Add to `docs/business/` (excluded from git)
3. **Is it compliance-related?** → Add to `docs/compliance/` (excluded from git)
4. **Is it internal process?** → Add to `docs/archive/` or exclude individually

### Reviewing Existing Files

Periodically review documentation to ensure:
- Sensitive information is not in public files
- Public documentation is up-to-date
- Private documentation is properly excluded

---

## Questions?

If unsure whether a document should be public or private, ask:

1. Does it contain business strategy or financial information? → **Private**
2. Does it contain partnership or customer details? → **Private**
3. Does it contain audit findings or vulnerabilities? → **Private**
4. Is it useful for external developers/users? → **Public**
5. Is it technical specification or architecture? → **Public**

When in doubt, default to **Private** and review later.

---

*This policy ensures the B4AE repository maintains appropriate separation between public technical documentation and private business/compliance materials.*
