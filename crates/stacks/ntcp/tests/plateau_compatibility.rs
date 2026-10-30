use ntcp::{Error, Ipv4Plateaus, PmtudConfig, PmtudPolicy};

#[test]
fn public_plateau_adapter_preserves_historical_bytes_defaults_and_error_type() {
    let historical = [
        65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
    ];
    assert_eq!(Ipv4Plateaus::CAPACITY, 16);
    assert_eq!(Ipv4Plateaus::RFC1191.as_slice(), historical);
    assert_eq!(Ipv4Plateaus::HISTORICAL.as_slice(), historical);
    assert_eq!(Ipv4Plateaus::default().as_slice(), historical);
    assert_eq!(PmtudPolicy::DEFAULT.ipv4_plateaus.as_slice(), historical);
    assert_eq!(
        PmtudConfig::new(1500).policy.ipv4_plateaus.as_slice(),
        historical
    );
    assert_eq!(
        Ipv4Plateaus::new(&historical).unwrap(),
        Ipv4Plateaus::RFC1191
    );
    assert_eq!(
        Ipv4Plateaus::CONTEMPORARY.as_slice(),
        &[65535, 9001, 8896, 8500, 1500, 1492, 1460, 576, 68]
    );
    for values in [&[][..], &[1500], &[65536, 68], &[1500, 1500, 68], &[67]] {
        let result: Result<Ipv4Plateaus, Error> = Ipv4Plateaus::new(values);
        assert_eq!(result, Err(Error::InvalidArgument));
        assert!(ntcp_path::Ipv4Plateaus::new(values).is_err());
    }
    for values in [
        &[68][..],
        &historical,
        Ipv4Plateaus::CONTEMPORARY.as_slice(),
        &[1600, 1400, 68],
    ] {
        assert_eq!(
            Ipv4Plateaus::new(values).unwrap().as_slice(),
            ntcp_path::Ipv4Plateaus::new(values).unwrap().as_slice()
        );
    }
}
