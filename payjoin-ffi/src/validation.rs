use std::time::Duration;

use payjoin::bitcoin::{Amount, FeeRate, ScriptBuf, Weight};

use crate::error::FfiValidationError;

const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_WITNESS_ITEMS: usize = 1000;
const MAX_WITNESS_BYTES: usize = 100_000;
// Note: These caps are conservative anti-DoS limits, not full Bitcoin Core
// relay policy (which is stricter per context, e.g., tapscript item 80 bytes,
// P2WSH witnessScript 3600 bytes, stack items 100). We keep FFI permissive
// while preventing unbounded memory/overflow; tighten here if you want policy parity.

pub(crate) fn validate_amount_sat(amount_sat: u64) -> Result<Amount, FfiValidationError> {
    let max_sat = Amount::MAX_MONEY.to_sat();
    if amount_sat > max_sat {
        return Err(FfiValidationError::AmountOutOfRange { amount_sat, max_sat });
    }
    Ok(Amount::from_sat(amount_sat))
}

pub(crate) fn validate_script_vec(
    field: &'static str,
    bytes: Vec<u8>,
    allow_empty: bool,
) -> Result<ScriptBuf, FfiValidationError> {
    validate_script_bytes(field, &bytes, allow_empty)?;
    Ok(ScriptBuf::from_bytes(bytes))
}

pub(crate) fn validate_optional_script(
    field: &'static str,
    bytes: Option<Vec<u8>>,
) -> Result<Option<ScriptBuf>, FfiValidationError> {
    match bytes {
        Some(bytes) => Ok(Some(validate_script_vec(field, bytes, false)?)),
        None => Ok(None),
    }
}

pub(crate) fn validate_script_bytes(
    field: &'static str,
    bytes: &[u8],
    allow_empty: bool,
) -> Result<(), FfiValidationError> {
    if !allow_empty && bytes.is_empty() {
        return Err(FfiValidationError::ScriptEmpty { field: field.to_string() });
    }
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(FfiValidationError::ScriptTooLarge {
            field: field.to_string(),
            len: bytes.len() as u64,
            max: MAX_SCRIPT_BYTES as u64,
        });
    }
    Ok(())
}

pub(crate) fn validate_witness_stack(witness: &[Vec<u8>]) -> Result<(), FfiValidationError> {
    if witness.len() > MAX_WITNESS_ITEMS {
        return Err(FfiValidationError::WitnessItemsTooMany {
            count: witness.len() as u64,
            max: MAX_WITNESS_ITEMS as u64,
        });
    }

    let mut total = 0usize;
    for (index, item) in witness.iter().enumerate() {
        if item.len() > MAX_SCRIPT_BYTES {
            return Err(FfiValidationError::WitnessItemTooLarge {
                index: index as u64,
                len: item.len() as u64,
                max: MAX_SCRIPT_BYTES as u64,
            });
        }
        total = total.saturating_add(item.len());
    }

    if total > MAX_WITNESS_BYTES {
        return Err(FfiValidationError::WitnessTooLarge {
            len: total as u64,
            max: MAX_WITNESS_BYTES as u64,
        });
    }

    Ok(())
}

pub(crate) fn validate_weight_units(weight_units: u64) -> Result<Weight, FfiValidationError> {
    let max_wu = Weight::MAX_BLOCK.to_wu();
    if weight_units == 0 || weight_units > max_wu {
        return Err(FfiValidationError::WeightOutOfRange { weight_units, max_wu });
    }
    Ok(Weight::from_wu(weight_units))
}

pub(crate) fn validate_fee_rate_sat_per_vb(value: u64) -> Result<FeeRate, FfiValidationError> {
    let fee_rate = FeeRate::from_sat_per_vb(value).ok_or_else(|| {
        FfiValidationError::FeeRateOutOfRange { value, unit: "sat/vB".to_string() }
    })?;
    if fee_rate.checked_mul_by_weight(Weight::MAX_BLOCK).is_none() {
        return Err(FfiValidationError::FeeRateOutOfRange { value, unit: "sat/vB".to_string() });
    }
    Ok(fee_rate)
}

pub(crate) fn validate_fee_rate_sat_per_kwu(value: u64) -> Result<FeeRate, FfiValidationError> {
    let fee_rate = FeeRate::from_sat_per_kwu(value);
    if fee_rate.checked_mul_by_weight(Weight::MAX_BLOCK).is_none() {
        return Err(FfiValidationError::FeeRateOutOfRange { value, unit: "sat/kwu".to_string() });
    }
    Ok(fee_rate)
}

pub(crate) fn validate_fee_rate_sat_per_vb_opt(
    value: Option<u64>,
) -> Result<Option<FeeRate>, FfiValidationError> {
    value.map(validate_fee_rate_sat_per_vb).transpose()
}

pub(crate) fn validate_fee_rate_sat_per_kwu_opt(
    value: Option<u64>,
) -> Result<Option<FeeRate>, FfiValidationError> {
    value.map(validate_fee_rate_sat_per_kwu).transpose()
}

pub(crate) fn validate_expiration_secs(seconds: u64) -> Result<Duration, FfiValidationError> {
    let max = u32::MAX as u64;
    if seconds > max {
        return Err(FfiValidationError::ExpirationOutOfRange { seconds, max });
    }
    Ok(Duration::from_secs(seconds))
}
