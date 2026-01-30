//! Artifact collection and serialization for work execution.
//!
//! Artifacts are structured data produced during work execution that provide
//! additional context beyond the raw output summary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An artifact produced during work execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Artifact type (e.g., "commit", "pr", "test_results", "log")
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,

    /// Human-readable name
    pub name: String,

    /// Artifact data (type-specific)
    pub data: ArtifactData,

    /// When the artifact was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Known artifact types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// Git commit information
    Commit,
    /// Pull request information
    PullRequest,
    /// Test execution results
    TestResults,
    /// Build output
    Build,
    /// Execution log/trace
    Log,
    /// Code coverage report
    Coverage,
    /// Benchmark results
    Benchmark,
    /// Diff/patch
    Diff,
    /// Screenshot or image
    Screenshot,
    /// Custom artifact
    Custom,
}

/// Type-specific artifact data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArtifactData {
    Commit(CommitArtifact),
    PullRequest(PullRequestArtifact),
    TestResults(TestResultsArtifact),
    Log(LogArtifact),
    Generic(GenericArtifact),
}

/// Git commit artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitArtifact {
    /// Full commit hash
    pub hash: String,
    /// Short commit hash (7 chars)
    pub short_hash: String,
    /// Commit message
    pub message: String,
    /// Author name/email
    pub author: String,
    /// Branch name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// Pull request artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestArtifact {
    /// PR number
    pub number: u64,
    /// PR title
    pub title: String,
    /// PR URL
    pub url: String,
    /// Source branch
    pub head_branch: String,
    /// Target branch
    pub base_branch: String,
    /// PR state (open, merged, closed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Test results artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResultsArtifact {
    /// Total tests run
    pub total: u32,
    /// Tests passed
    pub passed: u32,
    /// Tests failed
    pub failed: u32,
    /// Tests skipped
    pub skipped: u32,
    /// Execution time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    /// Failed test names
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub failures: Vec<String>,
}

/// Log/trace artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogArtifact {
    /// Log level (info, debug, error, etc.)
    pub level: String,
    /// Log content (may be truncated)
    pub content: String,
    /// Total lines (if truncated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<u32>,
}

/// Generic key-value artifact for custom data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericArtifact {
    /// Arbitrary key-value data
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

/// Collector for artifacts during work execution
#[derive(Debug, Default)]
pub struct ArtifactCollector {
    artifacts: Vec<Artifact>,
}

impl ArtifactCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a commit artifact
    pub fn add_commit(&mut self, hash: &str, message: &str, author: &str, branch: Option<&str>) {
        self.artifacts.push(Artifact {
            artifact_type: ArtifactType::Commit,
            name: format!("Commit {}", &hash[..7.min(hash.len())]),
            data: ArtifactData::Commit(CommitArtifact {
                hash: hash.to_string(),
                short_hash: hash[..7.min(hash.len())].to_string(),
                message: message.to_string(),
                author: author.to_string(),
                branch: branch.map(ToString::to_string),
            }),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
    }

    /// Add a pull request artifact
    pub fn add_pull_request(
        &mut self,
        number: u64,
        title: &str,
        url: &str,
        head_branch: &str,
        base_branch: &str,
    ) {
        self.artifacts.push(Artifact {
            artifact_type: ArtifactType::PullRequest,
            name: format!("PR #{number}"),
            data: ArtifactData::PullRequest(PullRequestArtifact {
                number,
                title: title.to_string(),
                url: url.to_string(),
                head_branch: head_branch.to_string(),
                base_branch: base_branch.to_string(),
                state: Some("open".to_string()),
            }),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
    }

    /// Add test results artifact
    pub fn add_test_results(
        &mut self,
        total: u32,
        passed: u32,
        failed: u32,
        skipped: u32,
        failures: Vec<String>,
    ) {
        self.artifacts.push(Artifact {
            artifact_type: ArtifactType::TestResults,
            name: format!("Test Results ({passed}/{total} passed)"),
            data: ArtifactData::TestResults(TestResultsArtifact {
                total,
                passed,
                failed,
                skipped,
                duration_secs: None,
                failures,
            }),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
    }

    /// Add a log artifact
    pub fn add_log(&mut self, name: &str, level: &str, content: &str) {
        let lines = content.lines().count() as u32;
        let truncated = if content.len() > 10000 {
            &content[..10000]
        } else {
            content
        };

        self.artifacts.push(Artifact {
            artifact_type: ArtifactType::Log,
            name: name.to_string(),
            data: ArtifactData::Log(LogArtifact {
                level: level.to_string(),
                content: truncated.to_string(),
                total_lines: if content.len() > 10000 {
                    Some(lines)
                } else {
                    None
                },
            }),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
    }

    /// Add a generic artifact with custom data
    pub fn add_custom(&mut self, name: &str, data: HashMap<String, serde_json::Value>) {
        self.artifacts.push(Artifact {
            artifact_type: ArtifactType::Custom,
            name: name.to_string(),
            data: ArtifactData::Generic(GenericArtifact { data }),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
    }

    /// Serialize all artifacts to JSON bytes
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.artifacts).unwrap_or_default()
    }

    /// Check if any artifacts have been collected
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Get the number of artifacts
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_artifact() {
        let mut collector = ArtifactCollector::new();
        collector.add_commit(
            "abc1234def5678",
            "Fix bug in login",
            "user@example.com",
            Some("main"),
        );

        assert_eq!(collector.len(), 1);

        let json = collector.to_json_bytes();
        let artifacts: Vec<Artifact> = serde_json::from_slice(&json).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::Commit);
    }

    #[test]
    fn test_pull_request_artifact() {
        let mut collector = ArtifactCollector::new();
        collector.add_pull_request(
            123,
            "Fix authentication bug",
            "https://github.com/org/repo/pull/123",
            "fix-auth",
            "main",
        );

        let json = collector.to_json_bytes();
        let artifacts: Vec<Artifact> = serde_json::from_slice(&json).unwrap();

        match &artifacts[0].data {
            ArtifactData::PullRequest(pr) => {
                assert_eq!(pr.number, 123);
                assert_eq!(pr.title, "Fix authentication bug");
            }
            _ => panic!("Expected PullRequest artifact"),
        }
    }

    #[test]
    fn test_test_results_artifact() {
        let mut collector = ArtifactCollector::new();
        collector.add_test_results(10, 8, 2, 0, vec!["test_login".to_string()]);

        let json = collector.to_json_bytes();
        let artifacts: Vec<Artifact> = serde_json::from_slice(&json).unwrap();

        match &artifacts[0].data {
            ArtifactData::TestResults(results) => {
                assert_eq!(results.total, 10);
                assert_eq!(results.passed, 8);
                assert_eq!(results.failed, 2);
                assert_eq!(results.failures.len(), 1);
            }
            _ => panic!("Expected TestResults artifact"),
        }
    }

    #[test]
    fn test_log_truncation() {
        let mut collector = ArtifactCollector::new();
        let long_content = "x".repeat(20000);
        collector.add_log("execution", "info", &long_content);

        let json = collector.to_json_bytes();
        let artifacts: Vec<Artifact> = serde_json::from_slice(&json).unwrap();

        match &artifacts[0].data {
            ArtifactData::Log(log) => {
                assert_eq!(log.content.len(), 10000);
                assert!(log.total_lines.is_some());
            }
            _ => panic!("Expected Log artifact"),
        }
    }
}
