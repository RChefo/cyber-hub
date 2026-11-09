//! Detection engineering: events read from samples, and the rule engines that run on them (Sigma
//! for logs). Rules are data; nothing in a rule or a sample is executed.

pub mod events;
pub mod sigma;
