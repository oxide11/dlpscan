//! Plugin system — custom validators and post-processors.
//!
//! Register per-sub_category validators to accept/reject matches,
//! and post-processors that transform the match list after scanning.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::models::Match;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A validator returns true if the match should be kept.
pub type ValidatorFn = Box<dyn Fn(&Match) -> bool + Send + Sync>;

/// A post-processor transforms a match list.
pub type PostProcessorFn = Box<dyn Fn(Vec<Match>) -> Vec<Match> + Send + Sync>;

// ---------------------------------------------------------------------------
// Global registries
// ---------------------------------------------------------------------------

static VALIDATORS: Mutex<Option<HashMap<String, Vec<ValidatorFn>>>> = Mutex::new(None);
static POST_PROCESSORS: Mutex<Option<Vec<PostProcessorFn>>> = Mutex::new(None);

fn with_validators<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Vec<ValidatorFn>>) -> R,
{
    let mut guard = VALIDATORS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn with_post_processors<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<PostProcessorFn>) -> R,
{
    let mut guard = POST_PROCESSORS.lock().unwrap_or_else(|e| e.into_inner());
    let list = guard.get_or_insert_with(Vec::new);
    f(list)
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Register a custom validator for a specific sub_category.
pub fn register_validator(sub_category: &str, validator: ValidatorFn) {
    with_validators(|map| {
        map.entry(sub_category.to_string())
            .or_default()
            .push(validator);
    });
}

/// Remove all validators for a sub_category.
pub fn unregister_validators(sub_category: &str) {
    with_validators(|map| {
        map.remove(sub_category);
    });
}

/// Run all registered validators for a match.
/// Returns true if the match passes all validators (or has none).
pub fn run_validators(m: &Match) -> bool {
    // Run under a single lock acquisition to avoid TOCTOU races
    with_validators(|map| {
        if let Some(validators) = map.get(&m.sub_category) {
            for validator in validators {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validator(m))) {
                    Ok(true) => {}
                    Ok(false) => return false,
                    Err(e) => {
                        tracing::error!("Validator panicked: {:?}", e);
                        return false; // fail-closed
                    }
                }
            }
        }
        true
    })
}

// ---------------------------------------------------------------------------
// Post-processors
// ---------------------------------------------------------------------------

/// Register a post-processor that transforms the match list.
pub fn register_post_processor(processor: PostProcessorFn) {
    with_post_processors(|list| {
        list.push(processor);
    });
}

/// Remove all registered post-processors.
pub fn unregister_post_processors() {
    with_post_processors(|list| {
        list.clear();
    });
}

/// Run all post-processors sequentially on the match list.
pub fn run_post_processors(matches: Vec<Match>) -> Vec<Match> {
    with_post_processors(|processors| {
        let mut current = matches;
        for processor in processors.iter() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| processor(current.clone()))) {
                Ok(result) => current = result,
                Err(e) => {
                    tracing::error!("Post-processor panicked: {:?}", e);
                }
            }
        }
        current
    })
}

/// Clear all validators and post-processors.
pub fn clear_all() {
    with_validators(|map| map.clear());
    with_post_processors(|list| list.clear());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(sub_cat: &str) -> Match {
        Match {
            text: "test".to_string(),
            category: "test".to_string(),
            sub_category: sub_cat.to_string(),
            has_context: false,
            confidence: 0.9,
            span: (0, 4),
            context_required: false,
        }
    }

    #[test]
    fn test_no_validators_passes() {
        // Use a unique sub_category that no other test registers
        let m = make_match("__test_no_validators_unique__");
        assert!(run_validators(&m));
    }

    #[test]
    fn test_register_and_run_validator() {
        // Use a unique key to avoid cross-test interference from parallel execution
        let key = "__test_register_validator_unique__";
        register_validator(key, Box::new(|m: &Match| m.confidence > 0.5));
        let m = make_match(key);
        assert!(run_validators(&m));

        let mut low = make_match(key);
        low.confidence = 0.2;
        assert!(!run_validators(&low));
        unregister_validators(key);
    }

    #[test]
    fn test_unregister_validators() {
        let key = "__test_unregister_unique__";
        register_validator(key, Box::new(|_| false));
        unregister_validators(key);
        let m = make_match(key);
        assert!(run_validators(&m));
    }

    #[test]
    fn test_post_processor() {
        // Post-processors are global and additive; other parallel tests may
        // register their own.  We verify our processor ran by checking that the
        // low-confidence match is removed — any additional post-processors from
        // other tests could only remove *more* items, so the high-confidence
        // match surviving is the key assertion.
        register_post_processor(Box::new(|matches: Vec<Match>| {
            matches.into_iter().filter(|m| m.confidence > 0.5).collect()
        }));

        let mut low = make_match("__pp_low__");
        low.confidence = 0.3;
        let mut high = make_match("__pp_high__");
        high.confidence = 0.9;

        let result = run_post_processors(vec![low, high]);
        // The low-confidence match must be gone
        assert!(!result.iter().any(|m| m.sub_category == "__pp_low__"));
        // The high-confidence match should survive (unless another test's
        // post-processor removed it, which is unlikely with unique names)
        assert!(result.iter().any(|m| m.sub_category == "__pp_high__"));
    }
}
