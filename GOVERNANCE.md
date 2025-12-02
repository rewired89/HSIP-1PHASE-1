# HSIP Governance

## Overview

HSIP (Human-Secure Internet Protocol) is an open source project maintained by Rewired89 and Nyx Systems LLC. This document describes how decisions are made, how contributions are managed, and how the project is governed.

---

## Project Leadership

### Current Structure: Benevolent Dictator for Life (BDFL)

**Project Lead:** Rewired89  
**Organization:** Nyx Systems LLC  
**Contact:** nyxsystemsllc@gmail.com

As the original creator and primary maintainer, Rewired89 has final decision-making authority on:
- Protocol design and specifications
- Code merges and releases
- Project direction and roadmap
- Security disclosures and responses
- License and legal matters

**Rationale:** Early-stage project benefits from clear leadership and fast decision-making. As the project matures, governance will evolve toward more community involvement.

---

## Future Governance Evolution

### Phase 1: Current (2025-2026)
**Model:** BDFL (single maintainer)
- Fast decision-making
- Clear responsibility
- Focused vision

### Phase 2: Core Team (2026-2027)
**Model:** Small core team (3-5 maintainers)
- Multiple trusted maintainers with commit access
- Consensus-based decisions on major changes
- Faster response to issues and PRs
- Geographic and expertise diversity

### Phase 3: Foundation (2027+)
**Model:** Non-profit foundation or working group
- Broad stakeholder representation
- Formal governance structure (board, committees)
- Transparent decision-making process
- Vendor-neutral stewardship

---

## Decision-Making Process

### Technical Decisions

#### Minor Changes (Bug Fixes, Docs, Small Features)
**Process:**
1. Contributor submits PR with clear description
2. Automated tests must pass
3. Maintainer reviews (usually within 1 week)
4. If approved, maintainer merges
5. Included in next release

**Decision Maker:** Project lead or delegated maintainer

#### Major Changes (Protocol Changes, Breaking API, Architecture)
**Process:**
1. Open GitHub Discussion proposing change
2. Community provides feedback (minimum 2 weeks)
3. Proposal refined based on feedback
4. Project lead makes final decision
5. Implementation proceeds if approved
6. Design rationale documented in /docs

**Decision Maker:** Project lead, informed by community input

**Examples of major changes:**
- Changing cryptographic algorithms
- Breaking wire protocol compatibility
- Removing features or APIs
- Major architectural refactors

#### Security Issues
**Process:**
1. Reported privately to nyxsystemsllc@gmail.com
2. Acknowledged within 48 hours
3. Project lead assesses severity
4. Fix developed in private
5. Security advisory published after fix released
6. CVE assigned if applicable

**Decision Maker:** Project lead (immediate action, no waiting for consensus)

---

## Contribution Process

### How to Contribute

1. **Small Fixes:** Just submit a PR
   - Typos in documentation
   - Small bug fixes (<50 lines)
   - Adding tests

2. **Features:** Discuss first, then implement
   - Open GitHub Discussion describing feature
   - Wait for feedback (at least 3 days)
   - Proceed if maintainer approves direction
   - Submit PR when ready

3. **Large Changes:** RFC (Request for Comments) process
   - Write design document (see /docs/rfcs for template)
   - Post as GitHub Discussion
   - Community and maintainers provide feedback
   - Revised based on feedback
   - Final decision by project lead
   - Implementation proceeds if approved

### Code Review Standards

All code (including from project lead) must:
- ✅ Pass automated tests
- ✅ Pass clippy lints (no warnings)
- ✅ Include tests for new functionality
- ✅ Update documentation if needed
- ✅ Maintain or improve test coverage
- ✅ Follow project coding style (rustfmt)

**Timeframe:** Maintainers aim to review PRs within 1 week. Ping after 1 week if no response.

---

## Roles and Responsibilities

### Project Lead
**Responsibilities:**
- Final decision on all major changes
- Release management and versioning
- Security incident response
- Roadmap and strategic direction
- Representing project in public forums

**Current:** Rewired89

### Maintainers (Future)
**Responsibilities:**
- Review and merge pull requests
- Triage and respond to issues
- Minor releases and bug fixes
- Improve documentation and examples
- Community support and engagement

**Current:** None yet (project lead only)
**Future:** 2-4 additional maintainers by 2026

### Contributors
**Responsibilities:**
- Submit bug reports and feature requests
- Write code, documentation, tests
- Review others' pull requests
- Help answer community questions
- Spread the word about HSIP

**Current:** Growing community, all welcome!

### Users
**Responsibilities:**
- Provide feedback and bug reports
- Share use cases and experiences
- Help other users (forums, chat)
- Advocate for HSIP in appropriate contexts

---

## Becoming a Maintainer

Maintainership is earned through sustained, high-quality contributions:

**Criteria:**
- 6+ months of regular contributions
- 10+ merged non-trivial PRs
- Demonstrated understanding of codebase
- Good judgment in reviews and discussions
- Trustworthy and professional behavior
- Available for ongoing maintenance

**Process:**
1. Project lead identifies potential maintainer
2. Private invitation to join maintainer team
3. Trial period (3 months) with limited commit access
4. Full maintainer status if trial successful

**Note:** Early-stage project, no maintainers yet besides project lead. First maintainers likely by mid-2026.

---

## Conflict Resolution

### Technical Disagreements

1. **Discuss:** Open, respectful technical discussion
2. **Evidence:** Provide benchmarks, examples, references
3. **Compromise:** Seek middle ground when possible
4. **Decision:** Project lead makes final call if consensus not reached
5. **Document:** Rationale recorded for future reference

### Behavioral Issues

**Code of Conduct (Summary):**
- Be respectful and professional
- Assume good intent
- No harassment, discrimination, or abuse
- Constructive criticism, not personal attacks
- Respect maintainer decisions (even if you disagree)

**Enforcement:**
1. **First violation:** Private warning from maintainer
2. **Second violation:** Public warning and temporary ban (1 week)
3. **Third violation:** Permanent ban from project spaces

**Serious violations** (threats, doxxing, severe harassment): Immediate permanent ban.

---

## Transparency and Communication

### Public Decisions
All technical decisions are made publicly on GitHub:
- Issues for bug reports and feature requests
- Discussions for design proposals
- Pull Requests for code changes
- Releases with detailed changelogs

### Private Decisions
Only these are private:
- Security vulnerabilities (until fixed)
- Legal matters (contracts, licenses)
- Personal information about contributors
- Grant applications (until announced)

### Regular Updates
- **Release notes:** Every release documents changes
- **Monthly updates:** Blog post or GitHub Discussion summarizing progress
- **Roadmap:** Public roadmap updated quarterly

---

## Financial Governance

### Current (2025)
- No revenue yet
- Self-funded by project lead
- Grant applications in progress

### Future (with funding)
**Principles:**
- Transparent use of funds (public accounting)
- Developer compensation (fair pay for work)
- Community benefits (infrastructure, documentation)
- Reserves for sustainability (6 months runway)

**Spending Authority:**
- Project lead approves all expenditures
- Major expenses (>$5k) announced publicly
- Annual financial summary published

**Grant Funding:**
- Applied-for grants announced publicly
- Awarded grants and amounts disclosed
- Use of funds reported to community

**Enterprise License Revenue:**
- Customer names private (unless they want public acknowledgment)
- Revenue used for project sustainability
- Portion allocated to community initiatives

---

## Intellectual Property

### Copyright
- Contributors retain copyright on their contributions
- Contributors grant project perpetual license to use
- All code licensed under HSIP Community License (non-commercial)
- Enterprise commercial license available from Nyx Systems LLC

### Trademarks
- "HSIP" and logos owned by Nyx Systems LLC
- Community can use for non-commercial purposes
- Commercial use requires license

### Patents
- No patents on HSIP protocol or implementation
- Contributors agree not to assert patents against project
- Open invention network principles followed

---

## Changing Governance

This governance document can be modified by:
1. Proposal posted as GitHub Discussion
2. Community feedback period (minimum 30 days)
3. Final decision by project lead
4. Major changes (e.g., moving to foundation) require broad community support

**Version History:**
- v1.0 (December 2025): Initial governance document

---

## Summary

**Current Governance (2025):**
- Single maintainer (BDFL model)
- Community input welcomed but not binding
- Transparent decision-making on GitHub
- Evolving toward collaborative governance

**Future Governance (2027+):**
- Multiple maintainers (core team)
- Foundation or non-profit stewardship
- Formal stakeholder representation
- Mature, sustainable governance

---

## Questions?

**Governance questions:** nyxsystemsllc@gmail.com  
**Technical questions:** GitHub Discussions  
**Security issues:** nyxsystemsllc@gmail.com (private)

---

*Last Updated: December 2025*
