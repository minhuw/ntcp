use ntcp_path::{ContextId, Error, Ipv4Plateaus, Limits, PathService};

#[test]
fn canonical_historical_contemporary_and_validation() {
    assert_eq!(
        Ipv4Plateaus::RFC1191.as_slice(),
        &[
            65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68
        ]
    );
    assert_eq!(Ipv4Plateaus::HISTORICAL, Ipv4Plateaus::RFC1191);
    assert_eq!(Ipv4Plateaus::default(), Ipv4Plateaus::RFC1191);
    assert_eq!(
        Ipv4Plateaus::CONTEMPORARY.as_slice(),
        &[65535, 9001, 8896, 8500, 1500, 1492, 1460, 576, 68]
    );
    assert_eq!(Ipv4Plateaus::CAPACITY, 16);
    for invalid in [
        &[][..],
        &[1500],
        &[67],
        &[65536, 68],
        &[1500, 1500, 68],
        &[68, 1500, 68],
        &[1500, 69],
    ] {
        assert_eq!(Ipv4Plateaus::new(invalid), Err(Error::InvalidArgument));
    }
    let full = [
        65535, 32000, 18000, 10000, 9001, 8896, 8500, 4500, 2000, 1500, 1492, 1460, 1000, 576, 296,
        68,
    ];
    assert_eq!(Ipv4Plateaus::new(&full).unwrap().as_slice(), full);
    let too_many = [
        65535, 32000, 18000, 10000, 9001, 8896, 8500, 4500, 2000, 1500, 1492, 1460, 1000, 576, 296,
        100, 68,
    ];
    assert_eq!(Ipv4Plateaus::new(&too_many), Err(Error::InvalidArgument));
}

#[test]
fn contemporary_thresholds_and_bounded_strict_descent() {
    let table = Ipv4Plateaus::CONTEMPORARY;
    for (bound, expected) in [
        (65536, 65535),
        (65535, 9001),
        (9002, 9001),
        (9001, 8896),
        (8896, 8500),
        (8500, 1500),
        (1501, 1500),
        (1500, 1492),
        (1493, 1492),
        (1492, 1460),
        (1461, 1460),
        (1460, 576),
        (577, 576),
        (576, 68),
        (69, 68),
        (68, 68),
        (0, 68),
    ] {
        assert_eq!(table.next_lower(bound), expected, "bound {bound}");
    }
    let mut bound = 65536;
    for &expected in table.as_slice() {
        let next = table.next_lower(bound);
        assert_eq!(next, expected);
        assert!(next < bound);
        bound = next;
    }
    assert_eq!(table.next_lower(bound), 68);
}

#[test]
fn legacy_header_correction_uses_bytes_and_exact_sent_bound() {
    let table = Ipv4Plateaus::CONTEMPORARY;
    // At the estimate, subtract the actual 20/60-byte IP header before descent.
    assert_eq!(table.legacy_fallback(1500, 1500, 20, 1500), Ok(1460));
    assert_eq!(table.legacy_fallback(1500, 1500, 60, 1500), Ok(576));
    // Below the estimate there is no legacy header subtraction.
    assert_eq!(table.legacy_fallback(1500, 1493, 60, 1500), Ok(1492));
    assert_eq!(table.legacy_fallback(9001, 9001, 20, 9001), Ok(8896));
    assert_eq!(table.legacy_fallback(9001, 8896, 60, 8500), Ok(1500));
    assert_eq!(table.legacy_fallback(68, 68, 60, 68), Ok(68));
    assert_eq!(table.legacy_fallback(1500, 68, 20, 68), Ok(68));
    for args in [
        (67, 1500, 20, 1500),
        (1500, 1500, 5, 1500),
        (1500, 1500, 24, 65536),
        (1500, 1500, 61, 1500),
        (1500, 1500, 21, 1500),
        (1500, 19, 20, 1500),
    ] {
        assert_eq!(
            table.legacy_fallback(args.0, args.1, args.2, args.3),
            Err(Error::InvalidArgument)
        );
    }
    let historical = Ipv4Plateaus::RFC1191;
    assert_eq!(historical.legacy_fallback(1500, 1500, 20, 1500), Ok(1006));
    assert_eq!(historical.legacy_fallback(1500, 1492, 20, 1500), Ok(1006));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-7
//= type=test
//= reason=T7 canonical bounded16 IPv4 policy selects nine contemporary values from AWS EC2 and Google VPC MTU documentation, RFC2516 PPPoE and RFC791 wire/fallback/floor limits. PathService defaults to this compact policy and atomically replaces validated tables at runtime without source changes; public tests exercise historical/custom/contemporary replacement and fallback. The low-level ntcp adapter preserves historical defaults and Error compatibility. The Host owner also replaces the table at runtime through Host::admin_set_ipv4_plateaus (the Administration capability, the same validated PathService replacement), which the ntcp-pathctl utility's plateaus command reaches through the opt-in local control socket of the native runtime and tun_echo, the counterpart of the suggested ioctl (ntcp-path-control tests/control.rs).
//# We do not expect that the values in the table, especially for higher MTU levels, are going to be valid forever. The values given here are an implementation suggestion, NOT a specification or requirement. Implementors should use up-to-date references to pick a set of plateaus; it is important that the table not contain too many entries or the process of searching for a PMTU might waste Internet resources. Implementors should also make it convenient for customers without source code to update the table values in their systems (for example, the table in a BSD-derived Unix kernel could be changed using a new "ioctl" command).
fn live_service_selects_and_replaces_bounded_policy_without_forwarding_changes() {
    let mut service = PathService::new(
        ContextId::new(99),
        Limits {
            links: 0,
            sources: 0,
            source_owners: 0,
            routes: 0,
            paths: 2,
            clients: 2,
        },
        [1; 16],
    )
    .unwrap();
    assert_eq!(service.ipv4_plateaus(), Ipv4Plateaus::CONTEMPORARY);
    assert_eq!(service.ipv4_plateaus().next_lower(1500), 1492);
    let usage = service.usage();
    for table in [
        Ipv4Plateaus::RFC1191,
        Ipv4Plateaus::new(&[1500, 1400, 68]).unwrap(),
        Ipv4Plateaus::CONTEMPORARY,
    ] {
        let revision = service.revision();
        service.set_ipv4_plateaus(table).unwrap();
        assert_eq!(service.ipv4_plateaus(), table);
        assert_eq!(service.revision(), revision + 1);
        assert_eq!(service.usage(), usage);
        service.set_ipv4_plateaus(table).unwrap();
        assert_eq!(service.revision(), revision + 1);
    }
    assert_eq!(
        service
            .ipv4_plateaus()
            .legacy_fallback(1500, 1500, 20, 1500),
        Ok(1460)
    );
}
