use std::{error, fmt};

use crate::receive::OutputSubstitutionError;

#[derive(Debug)]
pub struct ImplementationError(Box<dyn error::Error + Send + Sync>);

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError(Box::new(e))
    }
}

impl fmt::Display for ImplementationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.0.fmt(f) }
}

impl error::Error for ImplementationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> { Some(self.0.as_ref()) }
}

impl PartialEq for ImplementationError {
    fn eq(&self, _: &Self) -> bool { false }
}

impl Eq for ImplementationError {}

impl From<Box<dyn error::Error + Send + Sync>> for ImplementationError {
    fn from(e: Box<dyn error::Error + Send + Sync>) -> Self { ImplementationError(e) }
}

impl From<String> for ImplementationError {
    fn from(e: String) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}

impl From<&str> for ImplementationError {
    fn from(e: &str) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}

impl From<anyhow::Error> for ImplementationError {
    fn from(e: anyhow::Error) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}

impl From<bitcoin::address::FromScriptError> for ImplementationError {
    fn from(e: bitcoin::address::FromScriptError) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}

impl From<OutputSubstitutionError> for ImplementationError {
    fn from(e: OutputSubstitutionError) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}
