use sev_snp::{AttestationReport, SevSnp};

fn main() {
    // Initialise an SevSnp object
    let sev_snp = SevSnp::new().unwrap();

    // Retrieve an attestation report with default options passed to the hardware device
    let (report, _) = sev_snp.get_attestation_report().unwrap();
    let raw_bytes = bincode::serialize(&report.clone()).unwrap();
    println!("Attestation_bytes {:?}", raw_bytes);
    // println!("Attestation Report: {}", report);

    let rep: AttestationReport = bincode::deserialize(&raw_bytes.clone()).unwrap();

    // Verify the attestation report
    sev_snp.verify_attestation_report(&rep, None).unwrap();

    println!("Verification successful!");
}
