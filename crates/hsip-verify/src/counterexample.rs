//! Counterexample generation for failed security properties

use crate::SecurityProperty;
use std::collections::HashMap;
use std::fmt;

/// A counterexample demonstrating a violation of a security property
#[derive(Debug, Clone)]
pub struct Counterexample {
    property: SecurityProperty,
    details: HashMap<String, String>,
}

impl Counterexample {
    pub fn new(property: SecurityProperty, details: HashMap<String, String>) -> Self {
        Self { property, details }
    }

    pub fn property(&self) -> SecurityProperty {
        self.property
    }

    pub fn details(&self) -> &HashMap<String, String> {
        &self.details
    }

    /// Add a detail to the counterexample
    pub fn add_detail(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.details.insert(key.into(), value.into());
    }

    /// Get a specific detail
    pub fn get_detail(&self, key: &str) -> Option<&String> {
        self.details.get(key)
    }

    /// Generate a human-readable explanation
    pub fn explain(&self) -> String {
        let mut explanation = String::new();
        explanation.push_str(&format!("Counterexample for: {}\n", self.property));
        explanation.push_str("═══════════════════════════════════════════════\n");

        if let Some(desc) = self.details.get("description") {
            explanation.push_str(&format!("\n{}\n\n", desc));
        }

        explanation.push_str("Details:\n");
        for (key, value) in &self.details {
            if key != "description" {
                explanation.push_str(&format!("  • {}: {}\n", key, value));
            }
        }

        explanation
    }
}

impl fmt::Display for Counterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.explain())
    }
}

/// Builder for constructing counterexamples
pub struct CounterexampleBuilder {
    property: SecurityProperty,
    details: HashMap<String, String>,
}

impl CounterexampleBuilder {
    pub fn new(property: SecurityProperty) -> Self {
        Self {
            property,
            details: HashMap::new(),
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn with_description(self, description: impl Into<String>) -> Self {
        self.with_detail("description", description)
    }

    pub fn build(self) -> Counterexample {
        Counterexample::new(self.property, self.details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterexample_builder() {
        let ce = CounterexampleBuilder::new(SecurityProperty::ConsentNonForgery)
            .with_description("Test violation")
            .with_detail("key1", "value1")
            .with_detail("key2", "value2")
            .build();

        assert_eq!(ce.property(), SecurityProperty::ConsentNonForgery);
        assert_eq!(ce.get_detail("description"), Some(&"Test violation".to_string()));
        assert_eq!(ce.get_detail("key1"), Some(&"value1".to_string()));
    }
}
