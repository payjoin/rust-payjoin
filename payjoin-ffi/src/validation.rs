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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_sat_accepts_up_to_max_money_and_rejects_beyond() {
        let max_sat = Amount::MAX_MONEY.to_sat();
        assert!(validate_amount_sat(max_sat).is_ok());
        assert!(validate_amount_sat(0).is_ok());
        let err = validate_amount_sat(max_sat + 1).expect_err("should exceed max money");
        assert!(matches!(err, FfiValidationError::AmountOutOfRange { .. }));
    }

    #[test]
    fn script_bytes_enforces_empty_and_size_boundaries() {
        assert!(validate_script_bytes("script", b"", false).is_err());
        assert!(validate_script_bytes("script", b"", true).is_ok());
        assert!(validate_script_bytes("script", &vec![0; MAX_SCRIPT_BYTES], false).is_ok());
        let err = validate_script_bytes("script", &vec![0; MAX_SCRIPT_BYTES + 1], false)
            .expect_err("should exceed max script size");
        assert!(matches!(err, FfiValidationError::ScriptTooLarge { .. }));
    }

    #[test]
    fn script_vec_rejects_empty_when_disallowed() {
        assert!(validate_script_vec("script", Vec::new(), false).is_err());
        let script = validate_script_vec("script", vec![0x51], false).expect("valid script");
        assert_eq!(script, ScriptBuf::from_bytes(vec![0x51]));
    }

    #[test]
    fn optional_script_round_trips_none_and_some() {
        assert!(validate_optional_script("script", None).expect("None is valid").is_none());
        let script = validate_optional_script("script", Some(vec![0x51])).expect("Some is valid");
        assert_eq!(script, Some(ScriptBuf::from_bytes(vec![0x51])));
    }

    #[test]
    fn witness_stack_enforces_item_count_boundaries() {
        let max_items = vec![Vec::new(); MAX_WITNESS_ITEMS];
        assert!(validate_witness_stack(&max_items).is_ok());
        let too_many = vec![Vec::new(); MAX_WITNESS_ITEMS + 1];
        let err = validate_witness_stack(&too_many).expect_err("should exceed item count");
        assert!(matches!(err, FfiValidationError::WitnessItemsTooMany { .. }));
    }

    #[test]
    fn witness_stack_enforces_item_size_boundaries() {
        assert!(validate_witness_stack(&[vec![0; MAX_SCRIPT_BYTES]]).is_ok());
        let err = validate_witness_stack(&[vec![0; MAX_SCRIPT_BYTES + 1]])
            .expect_err("should exceed item size");
        assert!(matches!(err, FfiValidationError::WitnessItemTooLarge { .. }));
    }

    #[test]
    fn witness_stack_enforces_total_size_boundaries() {
        let at_limit = vec![vec![0; MAX_SCRIPT_BYTES]; MAX_WITNESS_BYTES / MAX_SCRIPT_BYTES];
        assert_eq!(at_limit.iter().map(|i| i.len()).sum::<usize>(), MAX_WITNESS_BYTES);
        assert!(validate_witness_stack(&at_limit).is_ok());
        let over_limit = vec![vec![0; MAX_SCRIPT_BYTES]; MAX_WITNESS_BYTES / MAX_SCRIPT_BYTES + 1];
        let err = validate_witness_stack(&over_limit).expect_err("should exceed total size");
        assert!(matches!(err, FfiValidationError::WitnessTooLarge { .. }));
    }

    #[test]
    fn weight_units_rejects_zero_and_above_max_block() {
        assert!(validate_weight_units(0).is_err());
        let max_wu = Weight::MAX_BLOCK.to_wu();
        assert_eq!(validate_weight_units(1).expect("valid weight"), Weight::from_wu(1));
        assert!(validate_weight_units(max_wu).is_ok());
        let err = validate_weight_units(max_wu + 1).expect_err("should exceed max block weight");
        assert!(matches!(err, FfiValidationError::WeightOutOfRange { .. }));
    }

    #[test]
    fn expiration_secs_accepts_u32_range_only() {
        assert_eq!(
            validate_expiration_secs(u32::MAX as u64).expect("valid expiration"),
            Duration::from_secs(u32::MAX as u64)
        );
        assert!(validate_expiration_secs(0).is_ok());
        let err = validate_expiration_secs(u32::MAX as u64 + 1)
            .expect_err("should exceed max expiration");
        assert!(matches!(err, FfiValidationError::ExpirationOutOfRange { .. }));
    }
}
