# Archive Directory

This directory contains internal documentation and tooling that has been archived for repository cleanup.

**These files are not part of the public HSIP commons project** - they were used during early development phases and are preserved here for historical reference only.

---

## What's Archived

### `/internal-docs/`
**Internal strategy and testing documentation**

- `SECURITY_HARDENING_STRATEGY.md` - Banking/enterprise security roadmap (internal planning)
- `SECURITY_TESTING.md` - Detailed security testing procedures (internal QA)
- `BUILD_INSTALLER.md` - Installer build instructions (developer-only)
- `TEST_RESULTS_SUMMARY.md` - Internal test result logs
- `WINDOWS_QUICK_START.md` - Internal testing quick-start guide

**Why archived**: These documents contained commercial/banking-focused language and internal planning details not appropriate for a public commons project.

### `/phase2-migration/`
**Scripts for migrating security fixes between project phases**

- `PORT_TO_PHASE2.ps1` - Automated security fix migration
- `FIX_PHASE2_BUILD.ps1` - Build error fixes
- `FIX_PHASE2_WORKSPACE.ps1` - Workspace configuration fixes
- `PROPER_PHASE2_FIX.ps1` - Complete Phase 2 security integration

**Why archived**: These were one-time migration scripts for internal project management, not relevant to public contributors.

### `/installer-docs/`
**Version-specific installer documentation**

- `RELEASE_NOTES_v0.2.1.md` - Internal release notes
- `BUILD_INSTRUCTIONS.md` - Detailed build process documentation

**Why archived**: Overly detailed internal build documentation. Public users should use the simplified guides in the main docs.

---

## Purpose of This Archive

The HSIP repository was reorganized for **NGI Zero Commons Fund** application to ensure the project presentation is:

- **Grant-appropriate** - Focused on commons, privacy, and user autonomy
- **Neutral and accessible** - No startup/VC/commercial framing
- **Developer-friendly** - Clear, simple, and public-facing documentation
- **Research-oriented** - Suitable for academic and non-profit evaluation

Archived files are preserved for:
- Historical reference
- Internal development continuity
- Future commercial licensing discussions (if needed)

---

## What This Means for Contributors

**You do NOT need these files to contribute to HSIP.**

The public-facing documentation provides everything needed to:
- Understand the protocol
- Build and test HSIP
- Contribute code or documentation
- Use HSIP in your projects

If you're working on HSIP and need something from this archive, ask in GitHub Issues or contact the maintainers.

---

## Restoring Archived Files

If you're a maintainer and need to restore a file:

```bash
# From repository root
git mv .archive/<subdirectory>/<filename> <destination>/
```

This archive is tracked in git for transparency and historical preservation.

---

**HSIP is commons infrastructure. These archives reflect our evolution toward that mission.**
