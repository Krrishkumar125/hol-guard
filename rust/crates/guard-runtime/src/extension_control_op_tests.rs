use super::*;
use guard_contracts::NativeExtensionControlV1;

const DIGEST_CHARS: &str = "a";
const ALPHA: &str = "command.alpha";
const BETA: &str = "command.beta";
const BETA_ALIAS: &str = "command.beta-legacy";
const GAMMA: &str = "command.gamma";
const ALPHA_READ: &str = "command.alpha.permission.read";
const ALPHA_WRITE: &str = "command.alpha.permission.write";
const BETA_RUN: &str = "command.beta.permission.run";
const GAMMA_DEPLOY: &str = "command.gamma.permission.deploy";

fn digest() -> String {
    DIGEST_CHARS.repeat(64)
}

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
}

fn disabled_extension(target_id: &str) -> NativeExtensionControlV1 {
    control("extension", target_id, "disabled")
}

fn enabled_extension(target_id: &str) -> NativeExtensionControlV1 {
    control("extension", target_id, "enabled")
}

fn disabled_permission(target_id: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, "disabled")
}

fn enabled_permission(target_id: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, "enabled")
}

fn layer(
    kind: &str,
    lockdown: bool,
    controls: Vec<NativeExtensionControlV1>,
) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        schema_version: "1.0.0".to_owned(),
        kind: kind.to_owned(),
        catalog_digest: digest(),
        global_lockdown: lockdown,
        controls,
    }
}

fn local(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("local-admin", false, controls)
}

fn cloud(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("signed-cloud", false, controls)
}

fn extension(
    id: &str,
    aliases: &[&str],
    dependencies: &[&str],
    required: bool,
    trust_class: &str,
) -> ExtensionControlRegistryExtensionV1 {
    ExtensionControlRegistryExtensionV1 {
        extension_id: id.to_owned(),
        aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required,
        trust_class: Some(trust_class.to_owned()),
    }
}

fn permission(
    id: &str,
    owner: &str,
    dependencies: &[&str],
    implied: &[&str],
) -> ExtensionControlRegistryPermissionV1 {
    ExtensionControlRegistryPermissionV1 {
        permission_id: id.to_owned(),
        extension_id: owner.to_owned(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        implied_permissions: implied.iter().map(|value| (*value).to_owned()).collect(),
    }
}

/// alpha (first-party), beta (external, aliased), gamma (required, depends on
/// alpha). gamma's deploy permission depends on alpha's write permission and
/// implies beta's run permission.
fn registry() -> ExtensionControlRegistryV1 {
    ExtensionControlRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![
            extension(ALPHA, &[], &[], false, "first-party"),
            extension(BETA, &[BETA_ALIAS], &[], false, "external"),
            extension(GAMMA, &[], &[ALPHA], true, "trusted-library"),
        ],
        permissions: vec![
            permission(ALPHA_READ, ALPHA, &[], &[]),
            permission(ALPHA_WRITE, ALPHA, &[], &[]),
            permission(BETA_RUN, BETA, &[], &[]),
            permission(GAMMA_DEPLOY, GAMMA, &[ALPHA_WRITE], &[BETA_RUN]),
        ],
    }
}

fn item(extensions: &[&str], permissions: &[&str]) -> ExtensionControlItemV1 {
    ExtensionControlItemV1 {
        extension_ids: extensions.iter().map(|value| (*value).to_owned()).collect(),
        permission_ids: permissions
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        active_extension_id: None,
    }
}

fn active_item(extension_id: &str) -> ExtensionControlItemV1 {
    ExtensionControlItemV1 {
        extension_ids: Vec::new(),
        permission_ids: Vec::new(),
        active_extension_id: Some(extension_id.to_owned()),
    }
}

fn scenario(
    layers: Vec<NativeExtensionControlLayerV1>,
    items: Vec<ExtensionControlItemV1>,
) -> ExtensionControlScenarioV1 {
    ExtensionControlScenarioV1 {
        layers,
        surface: "command-evaluation".to_owned(),
        authority_failure: None,
        items,
    }
}

fn request(query: ExtensionControlQueryV1) -> ExtensionControlRequestV1 {
    ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-1".to_owned(),
        query,
    }
}

fn resolve_request(scenarios: Vec<ExtensionControlScenarioV1>) -> ExtensionControlRequestV1 {
    request(ExtensionControlQueryV1::Resolve {
        registry: registry(),
        scenarios,
    })
}

fn run(request: &ExtensionControlRequestV1) -> ExtensionControlResultV1 {
    let bytes = evaluate_extension_control_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn resolved(scenarios: Vec<ExtensionControlScenarioV1>) -> Vec<ExtensionControlScenarioResultV1> {
    let result = run(&resolve_request(scenarios));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::Resolve { scenarios }) => scenarios,
        other => panic!("expected resolve payload, got {other:?}"),
    }
}

fn resolve_one(
    layers: Vec<NativeExtensionControlLayerV1>,
    item: ExtensionControlItemV1,
) -> ExtensionControlItemResultV1 {
    resolved(vec![scenario(layers, vec![item])])
        .remove(0)
        .results
        .remove(0)
}

fn composed(layers: Vec<NativeExtensionControlLayerV1>) -> ExtensionControlComposedV1 {
    let result = run(&request(ExtensionControlQueryV1::Compose { layers }));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::Compose { composed }) => composed,
        other => panic!("expected compose payload, got {other:?}"),
    }
}

fn error_code(request: &ExtensionControlRequestV1) -> String {
    let result = run(request);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
    result.code
}

fn failure_pairs(failures: &[ExtensionControlFailureV1]) -> Vec<(String, Option<String>)> {
    failures
        .iter()
        .map(|failure| (failure.code.clone(), failure.layer_kind.clone()))
        .collect()
}

fn failure_codes(failures: &[ExtensionControlFailureV1]) -> Vec<&str> {
    failures
        .iter()
        .map(|failure| failure.code.as_str())
        .collect()
}

#[test]
fn composition_is_permutation_independent_and_disable_dominates_enable() {
    let local_layer = local(vec![
        enabled_extension(ALPHA),
        disabled_permission(ALPHA_READ),
    ]);
    let cloud_layer = cloud(vec![
        disabled_extension(ALPHA),
        enabled_permission(ALPHA_READ),
    ]);
    let forward = composed(vec![local_layer.clone(), cloud_layer.clone()]);
    let reverse = composed(vec![cloud_layer, local_layer]);

    assert_eq!(forward, reverse);
    assert!(!forward.global_lockdown);
    assert!(forward.failures.is_empty());
    let states: Vec<(&str, &str, &str)> = forward
        .controls
        .iter()
        .map(|control| {
            (
                control.target_kind.as_str(),
                control.target_id.as_str(),
                control.state.as_str(),
            )
        })
        .collect();
    assert_eq!(
        states,
        vec![
            ("extension", ALPHA, "disabled"),
            ("permission", ALPHA_READ, "disabled"),
        ]
    );
}

#[test]
fn composition_reports_duplicates_sorted_by_string_value() {
    let duplicated = composed(vec![
        local(vec![disabled_extension(ALPHA), disabled_extension(ALPHA)]),
        local(Vec::new()),
    ]);

    assert_eq!(
        failure_pairs(&duplicated.failures),
        vec![
            (
                "duplicate-layer-kind".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "duplicate-target-in-layer".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn composition_takes_more_layers_than_the_resolver_admits_and_reports_them() {
    let three = composed(vec![
        local(Vec::new()),
        cloud(Vec::new()),
        local(Vec::new()),
    ]);

    assert_eq!(failure_codes(&three.failures), vec!["duplicate-layer-kind"]);
}

#[test]
fn composition_of_nothing_is_empty_and_unlocked() {
    let nothing = composed(Vec::new());

    assert!(!nothing.global_lockdown);
    assert!(nothing.controls.is_empty());
    assert!(nothing.failures.is_empty());
}

#[test]
fn lockdown_in_any_layer_locks_the_composition() {
    let locked = composed(vec![
        local(Vec::new()),
        layer("signed-cloud", true, Vec::new()),
    ]);

    assert!(locked.global_lockdown);
}

#[test]
fn an_unreadable_layer_is_a_bound_error_naming_the_layer() {
    for broken in [
        layer("unknown-kind", false, Vec::new()),
        NativeExtensionControlLayerV1 {
            schema_version: "2.0.0".to_owned(),
            ..local(Vec::new())
        },
        NativeExtensionControlLayerV1 {
            catalog_digest: "A".repeat(64),
            ..local(Vec::new())
        },
        local(vec![control("extension", ALPHA, "inherited")]),
        local(vec![control("extension", "not-a-catalog-id", "disabled")]),
        local(vec![control("permission", ALPHA, "disabled")]),
        local(vec![control("extension", ALPHA_READ, "disabled")]),
    ] {
        assert_eq!(
            error_code(&request(ExtensionControlQueryV1::Compose {
                layers: vec![broken.clone()]
            })),
            "native_extension_control_layer_invalid",
            "{broken:?}"
        );
        assert_eq!(
            error_code(&resolve_request(vec![scenario(
                vec![broken],
                vec![item(&[ALPHA], &[])]
            )])),
            "native_extension_control_layer_invalid"
        );
    }
}

#[test]
fn a_disabled_extension_permission_dependency_and_implication_each_block() {
    let cases: [(NativeExtensionControlV1, ExtensionControlItemV1, &str); 6] = [
        (
            disabled_extension(ALPHA),
            item(&[ALPHA], &[]),
            "control.disabled-extension",
        ),
        (
            disabled_permission(ALPHA_READ),
            item(&[], &[ALPHA_READ]),
            "control.disabled-permission",
        ),
        // gamma depends on alpha.
        (
            disabled_extension(ALPHA),
            item(&[GAMMA], &[]),
            "control.disabled-extension",
        ),
        // deploy depends on alpha's write permission.
        (
            disabled_permission(ALPHA_WRITE),
            item(&[], &[GAMMA_DEPLOY]),
            "control.disabled-permission",
        ),
        // deploy implies beta's run permission.
        (
            disabled_permission(BETA_RUN),
            item(&[], &[GAMMA_DEPLOY]),
            "control.disabled-permission",
        ),
        // A permission carries its owner: disabling the owner blocks it.
        (
            disabled_extension(ALPHA),
            item(&[], &[ALPHA_READ]),
            "control.disabled-extension",
        ),
    ];

    for (disabled, asked, reason) in cases {
        let answer = resolve_one(vec![local(vec![disabled.clone()])], asked);
        assert!(answer.blocked, "{disabled:?}");
        assert_eq!(answer.factor_reason_codes, vec![reason], "{disabled:?}");
        assert!(answer.failures.is_empty());
    }
}

#[test]
fn an_unrestricted_item_is_allowed_and_names_what_was_explicitly_enabled() {
    let answer = resolve_one(
        vec![local(vec![
            enabled_permission(ALPHA_WRITE),
            enabled_permission(ALPHA_READ),
        ])],
        item(&[ALPHA], &[ALPHA_WRITE, ALPHA_READ, BETA_RUN]),
    );

    assert!(!answer.blocked);
    assert!(answer.factor_reason_codes.is_empty());
    assert!(answer.failures.is_empty());
    assert_eq!(
        answer.explicitly_enabled_permission_ids,
        vec![ALPHA_READ.to_owned(), ALPHA_WRITE.to_owned()]
    );
    assert_eq!(answer.active, None);
}

#[test]
fn restrictions_never_reduce_the_resolved_action() {
    let subjects = [disabled_extension(ALPHA), disabled_permission(ALPHA_READ)];
    let mut blocked_by_subset = Vec::new();
    for mask in 0..(1 << subjects.len()) {
        let controls: Vec<NativeExtensionControlV1> = subjects
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, control)| control.clone())
            .collect();
        let answer = resolve_one(vec![local(controls)], item(&[ALPHA], &[ALPHA_READ]));
        blocked_by_subset.push((mask, answer.blocked));
    }

    assert!(blocked_by_subset
        .iter()
        .all(|(mask, blocked)| *blocked == (*mask != 0)));
}

#[test]
fn global_lockdown_blocks_commands_and_allows_only_typed_local_recovery() {
    let locked = vec![layer("local-admin", true, Vec::new())];
    let mut recovery = scenario(locked.clone(), vec![item(&[], &[])]);
    recovery.surface = "trusted-local-recovery".to_owned();
    let mut proof = scenario(locked.clone(), vec![item(&[], &[])]);
    proof.surface = "trusted-local-proof".to_owned();
    let command = scenario(locked, vec![item(&[ALPHA], &[ALPHA_READ])]);

    let answers = resolved(vec![command, recovery, proof]);

    assert!(answers.iter().all(|answer| answer.global_lockdown));
    assert!(answers[0].results[0].blocked);
    assert_eq!(
        answers[0].results[0].factor_reason_codes,
        vec!["control.global-lockdown"]
    );
    for answer in &answers[1..] {
        assert!(!answer.results[0].blocked);
        assert!(answer.results[0].factor_reason_codes.is_empty());
    }
}

#[test]
fn one_request_resolves_every_scenario_against_its_own_layers() {
    let answers = resolved(vec![
        scenario(Vec::new(), vec![item(&[ALPHA], &[]), item(&[BETA], &[])]),
        scenario(
            vec![local(vec![disabled_extension(BETA)])],
            vec![item(&[ALPHA], &[]), item(&[BETA], &[])],
        ),
        scenario(Vec::new(), Vec::new()),
    ]);

    let blocked: Vec<Vec<bool>> = answers
        .iter()
        .map(|answer| answer.results.iter().map(|item| item.blocked).collect())
        .collect();
    assert_eq!(
        blocked,
        vec![vec![false, false], vec![false, true], Vec::new()]
    );
}

#[test]
fn resolver_failures_are_typed_and_sorted_by_string_value() {
    // A digest mismatch and a duplicate layer kind sort the other way round
    // in the resolver's own declaration order.
    let mut stale = local(Vec::new());
    stale.catalog_digest = "b".repeat(64);
    let answer = resolve_one(vec![stale, local(Vec::new())], item(&[ALPHA], &[]));

    assert!(answer.blocked);
    assert_eq!(answer.factor_reason_codes, vec!["control.resolver-failure"]);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![
            (
                "catalog-digest-mismatch".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "duplicate-layer-kind".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn an_unknown_target_is_a_typed_failure_that_never_echoes_the_input() {
    let answer = resolve_one(Vec::new(), item(&["command.private-unknown-input"], &[]));

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![("unknown-extension-target".to_owned(), None)]
    );
    assert!(!format!("{answer:?}").contains("private-unknown-input"));
    let unknown_permission = resolve_one(
        Vec::new(),
        item(&[], &["command.private-unknown-input.permission.x"]),
    );
    assert_eq!(
        failure_codes(&unknown_permission.failures),
        vec!["unknown-permission-target"]
    );
}

#[test]
fn a_layer_built_for_another_catalog_blocks_every_item() {
    let mut other = local(vec![disabled_extension(ALPHA)]);
    other.catalog_digest = "0".repeat(64);
    let answer = resolve_one(vec![other], item(&[ALPHA], &[]));

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![(
            "catalog-digest-mismatch".to_owned(),
            Some("local-admin".to_owned())
        )]
    );
}

#[test]
fn a_duplicate_target_in_a_layer_fails_closed() {
    let answer = resolve_one(
        vec![local(vec![
            disabled_extension(ALPHA),
            disabled_extension(ALPHA),
        ])],
        item(&[ALPHA], &[]),
    );

    assert!(answer.blocked);
    assert_eq!(
        failure_codes(&answer.failures),
        vec!["duplicate-target-in-layer"]
    );
}

#[test]
fn a_control_aimed_at_an_alias_is_non_canonical_not_a_missing_disabled_control() {
    let answer = resolve_one(
        vec![local(vec![disabled_extension(BETA_ALIAS)])],
        item(&[BETA], &[]),
    );

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![(
            "non-canonical-target".to_owned(),
            Some("local-admin".to_owned())
        )]
    );
}

#[test]
fn a_control_for_a_target_the_registry_lacks_is_a_typed_failure() {
    let answer = resolve_one(
        vec![local(vec![
            disabled_extension("command.missing"),
            disabled_permission("command.missing.permission.x"),
        ])],
        item(&[ALPHA], &[]),
    );

    assert_eq!(
        failure_pairs(&answer.failures),
        vec![
            (
                "unknown-extension-target".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "unknown-permission-target".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn lookups_follow_the_catalog_normalization() {
    // Extensions resolve through a trimmed, lowercased id or a listed alias;
    // permissions through a trimmed, lowercased id.
    for asked in [
        item(&["  COMMAND.BETA  "], &[]),
        item(&[BETA_ALIAS], &[]),
        item(&[], &[" COMMAND.BETA.PERMISSION.RUN "]),
    ] {
        let answer = resolve_one(vec![local(vec![disabled_extension(BETA)])], asked.clone());
        assert!(answer.blocked, "{asked:?}");
        assert_eq!(
            answer.factor_reason_codes,
            vec!["control.disabled-extension"]
        );
    }
}

#[test]
fn an_alias_is_matched_as_listed_and_a_later_listing_wins_a_shared_alias() {
    let blocked_asking = |registry: ExtensionControlRegistryV1, layers, asked: &str| {
        let result = run(&request(ExtensionControlQueryV1::Resolve {
            registry,
            scenarios: vec![scenario(layers, vec![item(&[asked], &[])])],
        }));
        let Some(ExtensionControlPayloadV1::Resolve { scenarios }) = result.payload else {
            panic!("expected resolve payload: {}", result.code);
        };
        scenarios[0].results[0].clone()
    };

    // The queried id is normalized, the listed alias is not, so an alias that
    // is not already lowercase is never reached.
    let mut mixed = registry();
    mixed.extensions[1].aliases = vec!["command.Mixed-Alias".to_owned()];
    for asked in ["command.Mixed-Alias", "command.mixed-alias"] {
        let answer = blocked_asking(mixed.clone(), Vec::new(), asked);
        assert!(answer.blocked, "{asked}");
        assert_eq!(
            failure_codes(&answer.failures),
            vec!["unknown-extension-target"]
        );
    }

    // Two extensions listing one alias: the later one owns it.
    let mut shared = registry();
    shared.extensions[0].aliases = vec!["command.shared".to_owned()];
    shared.extensions[1].aliases = vec!["command.shared".to_owned()];
    let beta_disabled = vec![local(vec![disabled_extension(BETA)])];
    let alpha_disabled = vec![local(vec![disabled_extension(ALPHA)])];
    assert!(blocked_asking(shared.clone(), beta_disabled, "command.shared").blocked);
    assert!(!blocked_asking(shared, alpha_disabled, "command.shared").blocked);
}

#[test]
fn input_limits_fail_closed_at_their_boundaries() {
    let boundary = |ids: usize| {
        let asked: Vec<String> = (0..ids).map(|_| ALPHA.to_owned()).collect();
        resolve_one(
            Vec::new(),
            ExtensionControlItemV1 {
                extension_ids: asked,
                permission_ids: Vec::new(),
                active_extension_id: None,
            },
        )
    };
    assert!(!boundary(1024).blocked);
    let over = boundary(1025);
    assert!(over.blocked);
    assert_eq!(failure_codes(&over.failures), vec!["input-limit-exceeded"]);

    let long = "command.".to_owned() + &"a".repeat(248);
    assert_eq!(long.len(), 256);
    assert!(!resolve_one(Vec::new(), item(&[long.as_str()], &[]))
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    let longer = format!("{long}a");
    assert_eq!(
        failure_codes(&resolve_one(Vec::new(), item(&[longer.as_str()], &[])).failures),
        vec!["input-limit-exceeded"]
    );

    let controls = |count: usize| -> Vec<NativeExtensionControlV1> {
        (0..count)
            .map(|index| {
                control(
                    "extension",
                    &format!("command.generated-{index}"),
                    "enabled",
                )
            })
            .collect()
    };
    let at_limit = resolve_one(vec![local(controls(512))], item(&[ALPHA], &[]));
    assert!(!at_limit
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    let over_limit = resolve_one(vec![local(controls(513))], item(&[ALPHA], &[]));
    assert!(over_limit.blocked);
    assert!(over_limit
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    // More layers than layer kinds is an input-limit failure, not a rejection.
    let layers = resolve_one(
        vec![local(Vec::new()), cloud(Vec::new()), local(Vec::new())],
        item(&[ALPHA], &[]),
    );
    assert!(layers.blocked);
    assert!(layers
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
}

#[test]
fn an_authority_failure_blocks_commands_but_not_the_trusted_proof() {
    let mut command = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    command.authority_failure = Some("authority-tampered".to_owned());
    let mut proof = command.clone();
    proof.surface = "trusted-local-proof".to_owned();
    let mut recovery = command.clone();
    recovery.surface = "trusted-local-recovery".to_owned();

    let answers = resolved(vec![command, proof, recovery]);

    assert!(answers[0].results[0].blocked);
    assert_eq!(
        failure_pairs(&answers[0].results[0].failures),
        vec![("authority-tampered".to_owned(), None)]
    );
    assert!(!answers[1].results[0].blocked);
    assert!(answers[1].results[0].failures.is_empty());
    assert!(answers[2].results[0].blocked);
}

#[test]
fn a_surface_or_authority_failure_the_op_does_not_know_is_a_bound_error() {
    let mut surface = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    surface.surface = "recovery/by-path".to_owned();
    assert_eq!(
        error_code(&resolve_request(vec![surface])),
        "native_extension_control_surface_invalid"
    );
    let mut failure = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    failure.authority_failure = Some("authority-fine".to_owned());
    assert_eq!(
        error_code(&resolve_request(vec![failure])),
        "native_extension_control_authority_failure_invalid"
    );
}

#[test]
fn an_extension_is_active_by_trust_class_and_local_admin_enablement() {
    let activity = |layers: Vec<NativeExtensionControlLayerV1>, extension_id: &str| {
        resolve_one(layers, active_item(extension_id)).active
    };

    // Required and non-external extensions are always active.
    assert_eq!(
        activity(vec![local(vec![disabled_extension(GAMMA)])], GAMMA),
        Some(true)
    );
    assert_eq!(activity(Vec::new(), ALPHA), Some(true));
    // An external one needs an explicit local-admin enable.
    assert_eq!(activity(Vec::new(), BETA), Some(false));
    assert_eq!(
        activity(vec![local(vec![enabled_extension(BETA)])], BETA),
        Some(true)
    );
    assert_eq!(
        activity(vec![cloud(vec![enabled_extension(BETA)])], BETA),
        Some(false)
    );
    // Disable dominates the explicit enable, from either layer.
    assert_eq!(
        activity(
            vec![
                local(vec![enabled_extension(BETA)]),
                cloud(vec![disabled_extension(BETA)])
            ],
            BETA
        ),
        Some(false)
    );
    // An owner the registry does not know is never active.
    assert_eq!(activity(Vec::new(), "command.unlisted"), Some(false));
}

#[test]
fn activity_and_blocking_are_answered_together_for_one_item() {
    let answer = resolve_one(
        vec![local(vec![enabled_extension(BETA)])],
        ExtensionControlItemV1 {
            extension_ids: vec![BETA.to_owned()],
            permission_ids: Vec::new(),
            active_extension_id: Some(BETA.to_owned()),
        },
    );

    assert!(!answer.blocked);
    assert_eq!(answer.active, Some(true));
}

#[test]
fn an_active_question_about_an_extension_without_a_trust_class_is_a_bound_error() {
    let mut classless = registry();
    classless.extensions[1].trust_class = None;

    // Resolving without an activity question never needs the class.
    let answered = run(&request(ExtensionControlQueryV1::Resolve {
        registry: classless.clone(),
        scenarios: vec![scenario(Vec::new(), vec![item(&[BETA], &[])])],
    }));
    assert_eq!(answered.status, "ok", "{}", answered.code);

    assert_eq!(
        error_code(&request(ExtensionControlQueryV1::Resolve {
            registry: classless,
            scenarios: vec![scenario(Vec::new(), vec![active_item(BETA)])],
        })),
        "native_extension_control_trust_class_missing"
    );
}

#[test]
fn a_registry_the_op_cannot_index_is_a_bound_error() {
    let mut duplicate_extension = registry();
    duplicate_extension
        .extensions
        .push(extension(ALPHA, &[], &[], false, "first-party"));
    let mut duplicate_permission = registry();
    duplicate_permission
        .permissions
        .push(permission(ALPHA_READ, ALPHA, &[], &[]));
    let mut unknown_class = registry();
    unknown_class.extensions[0].trust_class = Some("trusted".to_owned());

    for broken in [duplicate_extension, duplicate_permission, unknown_class] {
        assert_eq!(
            error_code(&request(ExtensionControlQueryV1::Resolve {
                registry: broken,
                scenarios: vec![scenario(Vec::new(), vec![item(&[ALPHA], &[])])],
            })),
            "native_extension_control_registry_invalid"
        );
    }
}

#[test]
fn a_request_over_the_scenario_or_item_limit_is_a_bound_error() {
    let scenarios: Vec<ExtensionControlScenarioV1> =
        (0..65).map(|_| scenario(Vec::new(), Vec::new())).collect();
    assert_eq!(
        error_code(&resolve_request(scenarios)),
        "native_extension_control_too_many_items"
    );
    let items: Vec<ExtensionControlItemV1> = (0..4097).map(|_| item(&[ALPHA], &[])).collect();
    assert_eq!(
        error_code(&resolve_request(vec![scenario(Vec::new(), items)])),
        "native_extension_control_too_many_items"
    );
    let at_limit: Vec<ExtensionControlItemV1> = (0..4096).map(|_| item(&[ALPHA], &[])).collect();
    assert_eq!(
        resolved(vec![scenario(Vec::new(), at_limit)])[0]
            .results
            .len(),
        4096
    );
}

#[test]
fn a_request_over_the_byte_limit_has_no_digest_to_bind() {
    let mut padded = registry();
    padded.extensions[0].aliases = vec!["a".repeat(EXTENSION_CONTROL_MAX_BYTES + 1)];
    let outcome = evaluate_extension_control_request(&request(ExtensionControlQueryV1::Resolve {
        registry: padded,
        scenarios: Vec::new(),
    }));

    assert_eq!(
        outcome,
        Err("native_extension_control_too_large".to_owned())
    );
}

#[test]
fn a_request_for_another_schema_is_a_bound_error() {
    let mut other = request(ExtensionControlQueryV1::Compose { layers: Vec::new() });
    other.schema = "guard-extension-control-request.v0".to_owned();

    assert_eq!(
        error_code(&other),
        "native_extension_control_schema_mismatch"
    );
}

#[test]
fn every_reply_is_bound_to_its_request_by_id_and_digest() {
    let asked = request(ExtensionControlQueryV1::Compose { layers: Vec::new() });
    let result = run(&asked);

    assert_eq!(result.schema, EXTENSION_CONTROL_RESULT_SCHEMA);
    assert_eq!(result.request_id, "extension-control-1");
    assert_eq!(
        result.request_sha256,
        request_digest_with_limit(&asked, EXTENSION_CONTROL_MAX_BYTES).unwrap()
    );
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let mut other = asked;
    other.request_id = "extension-control-2".to_owned();
    assert_ne!(run(&other).request_sha256, result.request_sha256);
}

#[test]
fn failures_with_and_without_a_layer_kind_order_by_string_with_none_first() {
    let ordered = failures_wire(&[
        ControlResolverFailure::new(
            ResolverFailureCode::UnknownExtensionTarget,
            Some(ControlLayerKind::SignedCloud),
        ),
        ControlResolverFailure::new(
            ResolverFailureCode::UnknownExtensionTarget,
            Some(ControlLayerKind::LocalAdmin),
        ),
        ControlResolverFailure::new(ResolverFailureCode::UnknownExtensionTarget, None),
        ControlResolverFailure::new(ResolverFailureCode::UnsupportedControlSchema, None),
        ControlResolverFailure::new(
            ResolverFailureCode::CatalogDigestMismatch,
            Some(ControlLayerKind::LocalAdmin),
        ),
    ]);

    assert_eq!(
        failure_pairs(&ordered),
        vec![
            (
                "catalog-digest-mismatch".to_owned(),
                Some("local-admin".to_owned())
            ),
            ("unknown-extension-target".to_owned(), None),
            (
                "unknown-extension-target".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "unknown-extension-target".to_owned(),
                Some("signed-cloud".to_owned())
            ),
            ("unsupported-control-schema".to_owned(), None),
        ]
    );
}

#[test]
fn the_registry_projection_denies_unknown_fields_and_defaults_nothing() {
    let mut value = serde_json::to_value(request(ExtensionControlQueryV1::Resolve {
        registry: registry(),
        scenarios: Vec::new(),
    }))
    .unwrap();
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value.clone()).is_ok());
    value["query"]["registry"]["extensions"][0]["unlisted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value.clone()).is_err());
    value["query"]["registry"]["extensions"][0]
        .as_object_mut()
        .unwrap()
        .remove("unlisted");
    value["query"]["registry"]["extensions"][0]
        .as_object_mut()
        .unwrap()
        .remove("aliases");
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value).is_err());
}
