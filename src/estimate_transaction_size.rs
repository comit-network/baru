use crate::avg_vbytes;

/// Estimate the virtual size of a transaction based on the number of inputs and outputs.
pub(crate) fn estimate_virtual_size(number_of_inputs: u64, number_of_outputs: u64) -> u64 {
    number_of_inputs * avg_vbytes::INPUT + number_of_outputs * avg_vbytes::OUTPUT + avg_vbytes::FEE
}
