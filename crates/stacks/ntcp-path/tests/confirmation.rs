use ntcp_path::*;

fn address(text: &str) -> ScopedAddress {
    ScopedAddress::new(text.parse().unwrap(), None).unwrap()
}

struct Fixture {
    service: PathService,
    link: LinkId,
    route: RouteId,
    request: PathRequest,
    shared: [ClientId; 2],
    isolated: ClientId,
}

fn fixture(ipv6: bool) -> Fixture {
    let limits = Limits {
        links: 2,
        sources: 2,
        source_owners: 2,
        routes: 4,
        paths: 4,
        clients: 4,
    };
    let mut service = PathService::new(ContextId::new(700), limits, [1; 16]).unwrap();
    let link = service.register_link(InterfaceKey(1), 9000).unwrap();
    let source = service
        .register_source(
            address(if ipv6 { "2001:db8::1" } else { "192.0.2.1" }),
            link,
        )
        .unwrap();
    let route = service
        .add_route(Route {
            destination: IpPrefix::new(
                (if ipv6 { "::" } else { "0.0.0.0" }).parse().unwrap(),
                0,
            )
            .unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 100,
        })
        .unwrap();
    let request = PathRequest {
        source,
        destination: address(if ipv6 {
            "2001:db8:1::99"
        } else {
            "198.51.100.99"
        }),
        dscp: Dscp::new(0).unwrap(),
    };
    let (a, _) = service.acquire(request).unwrap();
    let (b, _) = service.acquire(request).unwrap();
    let (isolated, _) = service
        .acquire(PathRequest {
            dscp: Dscp::new(46).unwrap(),
            ..request
        })
        .unwrap();
    let mut fixture = Fixture {
        service,
        link,
        route,
        request,
        shared: [a, b],
        isolated,
    };
    fixture.clean_all();
    fixture
}

impl Fixture {
    fn clean_all(&mut self) {
        for client in [self.shared[0], self.shared[1], self.isolated] {
            let stamp = self.service.snapshot(client).unwrap().stamp();
            self.service.acknowledge(client, stamp).unwrap();
        }
    }
    fn path(&self) -> PathId {
        self.service.snapshot(self.shared[0]).unwrap().path()
    }
    fn state(&self) -> (u64, Vec<(PathSnapshot, bool)>) {
        (
            self.service.revision(),
            [self.shared[0], self.shared[1], self.isolated]
                .into_iter()
                .map(|c| {
                    (
                        self.service.snapshot(c).unwrap(),
                        self.service.is_dirty(c).unwrap(),
                    )
                })
                .collect(),
        )
    }
}

#[test]
fn positive_confirmation_acceptance_and_rejection_matrix() {
    for ipv6 in [false, true] {
        let mut f = fixture(ipv6);
        let path = f.path();
        // Nothing learned yet: the first-hop budget is already in effect.
        assert_eq!(
            f.service.confirm_delivery(path, 9000, 0, 0, 0),
            Ok(DeliveryConfirmation::NotLarger)
        );
        assert_eq!(
            f.service.trusted_decrease_with_hold(path, 1400, 600),
            Ok(EstimateChange::Decreased)
        );
        f.clean_all();
        let learned = f.service.path_snapshot(path).unwrap();
        let negative = learned.negative_revision();
        assert_eq!(learned.retry_not_before(), 600);
        let before = f.state();
        let isolated_path = f.service.snapshot(f.isolated).unwrap().path();
        let floor = if ipv6 { 1280 } else { 68 };
        for (ip_len, revision, selected, now, expected) in [
            (4000, negative - 1, 600, 700, Ok(DeliveryConfirmation::StaleNegativeRevision)),
            (4000, negative + 1, 600, 700, Ok(DeliveryConfirmation::StaleNegativeRevision)),
            (4000, negative, 599, 700, Ok(DeliveryConfirmation::Held)),
            (4000, negative, 600, 599, Ok(DeliveryConfirmation::Held)),
            (9001, negative, 600, 700, Ok(DeliveryConfirmation::ExceedsFirstHop)),
            (1400, negative, 600, 700, Ok(DeliveryConfirmation::NotLarger)),
            (1300, negative, 600, 700, Ok(DeliveryConfirmation::NotLarger)),
            (floor - 1, negative, 600, 700, Err(Error::InvalidArgument)),
        ] {
            assert_eq!(
                f.service.confirm_delivery(path, ip_len, revision, selected, now),
                expected,
                "{ip_len} {revision} {selected} {now}"
            );
            assert_eq!(f.state(), before);
        }
        // An unlearned isolated class cannot be raised by this path's proof.
        assert_eq!(
            f.service.confirm_delivery(isolated_path, 4000, 0, 600, 700),
            Ok(DeliveryConfirmation::NotLarger)
        );
        assert_eq!(f.state(), before);

        // Exactly at the deadline: growth is recorded as a learned fact,
        // clients of this path only become dirty, and decrease identity and
        // hold are untouched.
        assert_eq!(
            f.service.confirm_delivery(path, 4000, negative, 600, 600),
            Ok(DeliveryConfirmation::Raised)
        );
        let raised = f.service.path_snapshot(path).unwrap();
        assert_eq!(raised.learned_mtu(), Some(4000));
        assert_eq!(raised.ip_packet_budget(), Ok(4000));
        assert_eq!(raised.negative_revision(), negative);
        assert_eq!(raised.retry_not_before(), 600);
        assert!(raised.version() > learned.version());
        assert_eq!(
            f.service.dirty_clients().collect::<Vec<_>>(),
            vec![f.shared[0], f.shared[1]]
        );
        assert_eq!(f.service.snapshot(f.isolated), Ok(before.1[2].0));
        f.clean_all();

        // Confirming the whole first hop still records a learned ceiling, so a
        // later physical increase cannot lift the path past what was proven.
        assert_eq!(
            f.service.confirm_delivery(path, 9000, negative, 700, 800),
            Ok(DeliveryConfirmation::Raised)
        );
        f.service.set_link_mtu(f.link, 9200).unwrap();
        let grown = f.service.path_snapshot(path).unwrap();
        assert_eq!(grown.learned_mtu(), Some(9000));
        assert_eq!(grown.ip_packet_budget(), Ok(9000));
        f.clean_all();

        // A replaced route invalidates the incarnation: no further proof.
        let route = f.service.route(f.route).unwrap();
        f.service.replace_route(f.route, Route { metric: 50, ..route }).unwrap();
        assert_eq!(
            f.service.confirm_delivery(path, 9100, negative, 700, 800),
            Err(Error::Invalidated)
        );
        let (_, rebound) = f.service.rebind(f.shared[0], f.request).unwrap();
        assert_ne!(rebound.path(), path);
        assert_eq!(rebound.learned_mtu(), None);
    }
}

#[test]
fn fresh_unchanged_report_blocks_growth_selected_before_it() {
    for ipv6 in [false, true] {
        let mut f = fixture(ipv6);
        let path = f.path();
        f.service.trusted_decrease_with_hold(path, 1400, 600).unwrap();
        let negative = f.service.path_snapshot(path).unwrap().negative_revision();
        assert_eq!(
            f.service.confirm_delivery(path, 4000, negative, 600, 700),
            Ok(DeliveryConfirmation::Raised)
        );
        f.clean_all();
        // A probe for 6000 is selected at 1000 under the same negative
        // revision. A fresh validated report at 1100 leaves the shared
        // estimate unchanged (5000 >= 4000) but restarts the hold.
        let before = f.service.path_snapshot(path).unwrap();
        assert_eq!(
            f.service.trusted_decrease_with_hold(path, 5000, 1700),
            Ok(EstimateChange::Unchanged)
        );
        let held = f.service.path_snapshot(path).unwrap();
        assert_eq!(held.learned_mtu(), Some(4000));
        assert_eq!(held.negative_revision(), negative);
        assert_eq!(held.retry_not_before(), 1700);
        assert!(held.version() > before.version());
        assert_eq!(
            f.service.dirty_clients().collect::<Vec<_>>(),
            vec![f.shared[0], f.shared[1]]
        );
        f.clean_all();
        // Delivery of the earlier selection proves nothing, even after the
        // restarted hold expires.
        for now in [1100, 1700, 5000] {
            assert_eq!(
                f.service.confirm_delivery(path, 6000, negative, 1000, now),
                Ok(DeliveryConfirmation::Held)
            );
        }
        // An older deadline or no hold changes nothing.
        let state = f.state();
        for deadline in [0, 1000, 1700] {
            assert_eq!(
                f.service.trusted_decrease_with_hold(path, 4000, deadline),
                Ok(EstimateChange::Unchanged)
            );
            assert_eq!(f.state(), state);
        }
        // Growth selected after the restarted hold remains possible.
        assert_eq!(
            f.service.confirm_delivery(path, 6000, negative, 1700, 1800),
            Ok(DeliveryConfirmation::Raised)
        );
        assert_eq!(f.service.path_snapshot(path).unwrap().learned_mtu(), Some(6000));
    }
}
