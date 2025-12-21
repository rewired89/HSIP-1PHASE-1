//! Security property definitions and results

use std::fmt;

/// Security properties that can be verified
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityProperty {
    /// Consent cannot be forged without the private key
    ConsentNonForgery,
    /// Revocation is temporally consistent (once revoked, always revoked)
    TemporalConsistency,
    /// Peer IDs are cryptographically bound to public keys
    IdentityBinding,
}

impl fmt::Display for SecurityProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityProperty::ConsentNonForgery => write!(f, "Consent Non-Forgery"),
            SecurityProperty::TemporalConsistency => write!(f, "Temporal Consistency"),
            SecurityProperty::IdentityBinding => write!(f, "Identity Binding Soundness"),
        }
    }
}

impl SecurityProperty {
    /// Get formal specification of the property
    pub fn formal_spec(&self) -> &'static str {
        match self {
            SecurityProperty::ConsentNonForgery => {
                "∀ consent, sig. valid(consent, sig, pk) ⟹ ∃ sk. sign(sk, consent) = sig ∧ derive(sk) = pk"
            }
            SecurityProperty::TemporalConsistency => {
                "∀ t1, t2. (revoked_at(t1) ∧ t2 > t1) ⟹ ¬allowed_at(t2)"
            }
            SecurityProperty::IdentityBinding => {
                "∀ peer_id, pk1, pk2. (peer_id = derive(pk1) ∧ peer_id = derive(pk2)) ⟹ pk1 = pk2"
            }
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SecurityProperty::ConsentNonForgery => {
                "A valid consent signature can only be created by the holder of the private key. \
                 This ensures that consent cannot be forged or fabricated by attackers."
            }
            SecurityProperty::TemporalConsistency => {
                "Once consent is revoked at time t, it remains revoked for all future times. \
                 This ensures that revocation is permanent and cannot be undone or bypassed."
            }
            SecurityProperty::IdentityBinding => {
                "Each peer ID uniquely identifies a single public key. \
                 This ensures that identity cannot be spoofed through hash collisions."
            }
        }
    }
}

/// Result of verifying a security property
#[derive(Debug, Clone)]
pub enum PropertyResult {
    /// Property is proven to hold
    Proven {
        property: SecurityProperty,
        proof: String,
    },
    /// Property is violated (counterexample found)
    Violated {
        property: SecurityProperty,
        counterexample: Option<crate::Counterexample>,
    },
    /// Verification inconclusive
    Unknown {
        property: SecurityProperty,
        reason: String,
    },
}

impl PropertyResult {
    pub fn is_proven(&self) -> bool {
        matches!(self, PropertyResult::Proven { .. })
    }

    pub fn is_violated(&self) -> bool {
        matches!(self, PropertyResult::Violated { .. })
    }

    pub fn property(&self) -> SecurityProperty {
        match self {
            PropertyResult::Proven { property, .. } => *property,
            PropertyResult::Violated { property, .. } => *property,
            PropertyResult::Unknown { property, .. } => *property,
        }
    }
}

impl fmt::Display for PropertyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyResult::Proven { property, proof } => {
                writeln!(f, "  Status: ✅ PROVEN")?;
                writeln!(f, "  Formal spec: {}", property.formal_spec())?;
                writeln!(f, "  Proof: {}", proof)
            }
            PropertyResult::Violated { property, counterexample } => {
                writeln!(f, "  Status: ❌ VIOLATED")?;
                writeln!(f, "  Formal spec: {}", property.formal_spec())?;
                if let Some(ce) = counterexample {
                    writeln!(f, "  Counterexample:")?;
                    for (key, value) in ce.details() {
                        writeln!(f, "    {}: {}", key, value)?;
                    }
                }
                Ok(())
            }
            PropertyResult::Unknown { property, reason } => {
                writeln!(f, "  Status: ⚠️  UNKNOWN")?;
                writeln!(f, "  Formal spec: {}", property.formal_spec())?;
                writeln!(f, "  Reason: {}", reason)
            }
        }
    }
}
