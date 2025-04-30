use std::error;

pub type ImplementationError = Box<dyn error::Error + Send + Sync>;
