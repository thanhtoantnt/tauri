// Oracle type: Algebraic (access-control decision function) + Invariant (deny precedence)
//
// Rejected stronger tiers:
//   - State Machine: resolve_access is a pure function over (acl, command, window, webview, origin)
//   - Reference: no independent implementation; this IS the security spec
//
// SUT: tauri::ipc::RuntimeAuthority::resolve_access
//   The core IPC authorization function. Given a (command, window, webview, origin),
//   returns Some(matching ResolvedCommand entries) if access is allowed, None otherwise.
//
//   Key rules (from the implementation):
//   1. DENY PRECEDENCE: a command present in denied_commands at all returns None
//      — unconditional on origin/context (the code does `.get(...).map(...).is_some()`,
//      discarding the per-context match result inside the closure).
//   2. ORIGIN FILTER: a resolved command is considered only if its ExecutionContext
//      matches the origin (Local↔Local, Remote↔Remote with URL-pattern test).
//   3. WINDOW/WEBVIEW FILTER: at least one window pattern OR at least one webview
//      pattern must match the input. Empty windows AND empty webviews is NEVER accessible.
//   4. UNKNOWN COMMAND: a command not in allowed_commands returns None.
//   5. FILTERED RETURN: the returned Vec contains only the matching entries
//      (not all entries for the command).
//
// Not testable from pbt-tests (require Runtime/StateManager):
//   - ScopeManager::get_*_scope_typed, CommandScope::matches, add_capability, __allow_command

use std::collections::BTreeMap;

use proptest::prelude::*;
use tauri::ipc::{Origin, RuntimeAuthority};
use tauri_utils::acl::{
  resolved::{Resolved, ResolvedCommand},
  ExecutionContext,
};

// ══════════════════════════════════════════════════════════════════════════
// Strategies
// ══════════════════════════════════════════════════════════════════════════

fn local_origin() -> impl Strategy<Value = Origin> {
  Just(Origin::Local)
}

fn remote_origin() -> impl Strategy<Value = Origin> {
  "https?://[a-z][a-z0-9-]{0,10}\\.[a-z]{2,5}".prop_map(|s| {
    Origin::Remote {
      url: s.parse().expect("hardcoded regex is a valid URL"),
    }
  })
}

fn any_origin() -> impl Strategy<Value = Origin> {
  prop_oneof![local_origin(), remote_origin()]
}

fn command_name() -> impl Strategy<Value = String> {
  prop::collection::vec(prop::char::range('a', 'z'), 1..=8)
    .prop_map(|cs| cs.into_iter().collect())
}

/// A label guaranteed to START with "main-", so it matches the glob "main-*".
fn main_dash_label() -> impl Strategy<Value = String> {
  prop::collection::vec(
    prop_oneof![prop::char::range('a', 'z'), prop::char::range('0', '9'), Just('-')],
    0..=5,
  )
  .prop_map(|cs: Vec<char>| format!("main-{}", cs.into_iter().collect::<String>()))
}

/// A label guaranteed NOT to start with "main-", so it does NOT match "main-*".
fn non_main_label() -> impl Strategy<Value = String> {
  prop::collection::vec(
    prop_oneof![prop::char::range('a', 'z'), prop::char::range('0', '9'), Just('-')],
    1..=10,
  )
  .prop_map(|cs: Vec<char>| cs.into_iter().collect::<String>())
  .prop_filter("must not start with main-", |s| !s.starts_with("main-"))
}

/// An arbitrary label of any shape.
fn any_label() -> impl Strategy<Value = String> {
  prop::collection::vec(
    prop_oneof![prop::char::range('a', 'z'), prop::char::range('0', '9'), Just('-')],
    1..=10,
  )
  .prop_map(|cs: Vec<char>| cs.into_iter().collect::<String>())
}

// ══════════════════════════════════════════════════════════════════════════
// Builder
// ══════════════════════════════════════════════════════════════════════════

fn build_authority(
  allowed: Vec<(String, Vec<ResolvedCommand>)>,
  denied: Vec<(String, Vec<ResolvedCommand>)>,
) -> RuntimeAuthority {
  RuntimeAuthority::new(
    Default::default(),
    Resolved {
      allowed_commands: allowed.into_iter().collect::<BTreeMap<_, _>>(),
      denied_commands: denied.into_iter().collect::<BTreeMap<_, _>>(),
      ..Default::default()
    },
  )
}

// ══════════════════════════════════════════════════════════════════════════
// 1. Origin filtering — context must match origin
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// A command allowed ONLY for the Local context is NOT accessible from a
  /// Remote origin. Origin filtering must drop the entry before the window check.
  #[test]
  fn local_only_command_blocked_from_remote_origin(
    command in command_name(),
    window in main_dash_label(),
    webview in any_label(),
    remote in remote_origin(),
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &window, &webview, &remote);
    assert!(result.is_none(),
      "Local-only command '{command}' must not be accessible from remote origin");
  }
}

proptest! {
  /// A command allowed ONLY for a specific Remote URL pattern is NOT accessible
  /// from a Local origin.
  #[test]
  fn remote_only_command_blocked_from_local_origin(
    command in command_name(),
    window in any_label(),
    webview in any_label(),
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Remote {
        url: "https://tauri.app".parse().unwrap(),
      },
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &window, &webview, &Origin::Local);
    assert!(result.is_none(),
      "Remote-only command '{command}' must not be accessible from local origin");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 2. Remote URL pattern matching
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// A command allowed for "https://*" (any HTTPS origin) is accessible from
  /// any Remote origin whose URL is HTTPS. Origin::Local must still be rejected.
  #[test]
  fn remote_wildcard_https_matches_any_https_url(
    command in command_name(),
    window in any_label(),
    webview in any_label(),
    url in "https://[a-z][a-z0-9-]{0,10}\\.[a-z]{2,5}",
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Remote {
        url: "https://*".parse().unwrap(),
      },
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let origin = Origin::Remote { url: url.parse().unwrap() };
    let result = auth.resolve_access(&command, &window, &webview, &origin);
    assert!(result.is_some(),
      "'https://*' should match {url} for command '{command}'");
  }
}

proptest! {
  /// A command allowed ONLY for the exact URL "https://tauri.app" is NOT
  /// accessible from a Remote origin with a different host.
  #[test]
  fn remote_exact_url_does_not_match_other_hosts(
    command in command_name(),
    window in any_label(),
    webview in any_label(),
    other_host in "[a-z][a-z0-9-]{0,10}\\.[a-z]{2,5}",
  ) {
    prop_assume!(!other_host.contains("tauri.app"));
    let resolved = ResolvedCommand {
      context: ExecutionContext::Remote {
        url: "https://tauri.app".parse().unwrap(),
      },
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let origin = Origin::Remote { url: format!("https://{other_host}").parse().unwrap() };
    let result = auth.resolve_access(&command, &window, &webview, &origin);
    assert!(result.is_none(),
      "'https://tauri.app' must not match https://{other_host}");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 3. Deny precedence (unconditional on origin)
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// If a command is in denied_commands at all, resolve_access returns None
  /// for ANY origin — even one that would match an allowed entry.
  /// This is because the implementation does
  /// `denied_commands.get(command).map(|v| ...).is_some()` which discards
  /// the per-context match inside the closure.
  #[test]
  fn deny_takes_precedence_over_allow_for_any_origin(
    command in command_name(),
    window in main_dash_label(),
    webview in any_label(),
    origin in any_origin(),
  ) {
    let allowed = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    // The denied entry is for a different context — yet the implementation
    // rejects all origins.
    let denied = ResolvedCommand {
      context: ExecutionContext::Remote {
        url: "https://*".parse().unwrap(),
      },
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![allowed])],
      vec![(command.clone(), vec![denied])],
    );
    let result = auth.resolve_access(&command, &window, &webview, &origin);
    assert!(result.is_none(),
      "command '{command}' is in denied_commands, must be None for any origin");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 4. Unknown command
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// A command not present in allowed_commands returns None.
  #[test]
  fn unknown_command_returns_none(
    requested in command_name(),
    known in command_name(),
    window in any_label(),
    webview in any_label(),
    origin in any_origin(),
  ) {
    prop_assume!(requested != known);
    let auth = build_authority(
      vec![(known, vec![ResolvedCommand {
        context: ExecutionContext::Local,
        windows: vec!["*".parse().unwrap()],
        ..Default::default()
      }])],
      vec![],
    );
    let result = auth.resolve_access(&requested, &window, &webview, &origin);
    assert!(result.is_none(), "unknown command '{requested}' must return None");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 5. Window glob matching
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// A command with window pattern "main-*" matches any label starting with "main-".
  #[test]
  fn window_glob_prefix_matches_matching_label(
    command in command_name(),
    suffix in "[a-z0-9-]{0,5}",
    webview in any_label(),
  ) {
    let label = format!("main-{suffix}");
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["main-*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &label, &webview, &Origin::Local);
    assert!(result.is_some(),
      "window pattern 'main-*' must match label '{label}'");
  }
}

proptest! {
  /// A command with window pattern "main-*" does NOT match a label that
  /// does not start with "main-".
  #[test]
  fn window_glob_prefix_rejects_non_matching_label(
    command in command_name(),
    label in non_main_label(),
    webview in any_label(),
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["main-*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &label, &webview, &Origin::Local);
    assert!(result.is_none(),
      "window pattern 'main-*' must NOT match label '{label}'");
  }
}

proptest! {
  /// A command with window pattern "*" matches any label.
  #[test]
  fn window_glob_wildcard_matches_any_label(
    command in command_name(),
    label in any_label(),
    webview in any_label(),
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &label, &webview, &Origin::Local);
    assert!(result.is_some(),
      "window pattern '*' must match any label, got rejection for '{label}'");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 6. Window OR webview matching
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// A ResolvedCommand with NO window patterns but a webview pattern that
  /// matches is still accessible (window OR webview is sufficient).
  #[test]
  fn webview_match_suffices_when_no_window_patterns(
    command in command_name(),
    window in any_label(),
    webview_suffix in "[a-z0-9-]{0,5}",
  ) {
    let wv_label = format!("webview-{webview_suffix}");
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec![],
      webviews: vec!["webview-*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &window, &wv_label, &Origin::Local);
    assert!(result.is_some(),
      "matching webview with empty windows must still be accessible");
  }
}

proptest! {
  /// A ResolvedCommand with NO webview patterns but a window pattern that
  /// matches is still accessible.
  #[test]
  fn window_match_suffices_when_no_webview_patterns(
    command in command_name(),
    suffix in "[a-z0-9-]{0,5}",
    webview in any_label(),
  ) {
    let label = format!("main-{suffix}");
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["main-*".parse().unwrap()],
      webviews: vec![],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &label, &webview, &Origin::Local);
    assert!(result.is_some(),
      "matching window with empty webviews must still be accessible");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 7. Empty windows AND empty webviews — never accessible
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// Subtle but important: a ResolvedCommand with BOTH windows and webviews
  /// empty is never accessible, regardless of the input labels.
  /// The implementation evaluates `any(windows) || any(webviews)`, and
  /// `false || false == false`. This is effectively a "deny all" command.
  #[test]
  fn empty_windows_and_webviews_is_never_accessible(
    command in command_name(),
    window in any_label(),
    webview in any_label(),
  ) {
    let resolved = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec![],
      webviews: vec![],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(command.clone(), vec![resolved])],
      vec![],
    );
    let result = auth.resolve_access(&command, &window, &webview, &Origin::Local);
    assert!(result.is_none(),
      "empty windows AND empty webviews must never match (deny-all by construction)");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 8. Filtered return: only matching entries are returned
// ══════════════════════════════════════════════════════════════════════════

proptest! {
  /// When multiple ResolvedCommand entries exist for the same command,
  /// only the ones matching all criteria (context + window OR webview) are
  /// returned. Non-matching entries are silently dropped.
  #[test]
  fn only_matching_entries_returned(
    command in command_name(),
    suffix in "[a-z0-9-]{0,5}",
    webview in any_label(),
  ) {
    let label = format!("main-{suffix}");
    let matching = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["main-*".parse().unwrap()],
      ..Default::default()
    };
    let wrong_context = ResolvedCommand {
      context: ExecutionContext::Remote {
        url: "https://tauri.app".parse().unwrap(),
      },
      windows: vec!["main-*".parse().unwrap()],
      ..Default::default()
    };
    let wrong_window = ResolvedCommand {
      context: ExecutionContext::Local,
      windows: vec!["other-*".parse().unwrap()],
      ..Default::default()
    };
    let auth = build_authority(
      vec![(
        command.clone(),
        vec![matching.clone(), wrong_context, wrong_window],
      )],
      vec![],
    );
    let result = auth.resolve_access(&command, &label, &webview, &Origin::Local);
    let returned = result.expect("matching entry must be returned");
    assert_eq!(returned.len(), 1,
      "only the matching entry should be returned for label '{label}'");
    assert_eq!(returned[0], matching,
      "the returned entry must be the matching one");
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 9. Origin::Display
// ══════════════════════════════════════════════════════════════════════════

#[test]
fn origin_local_displays_as_local() {
  assert_eq!(Origin::Local.to_string(), "local");
}

proptest! {
  /// Origin::Remote displays as "remote: {url}".
  #[test]
  fn origin_remote_displays_with_url_prefix(url in "https?://[a-z]+\\.[a-z]{2,5}") {
    let origin = Origin::Remote { url: url.parse().unwrap() };
    let display = origin.to_string();
    assert!(display.starts_with("remote: "),
      "Display should start with 'remote: ', got: {display}");
    assert!(display.contains(&url),
      "Display should contain the URL '{url}', got: {display}");
  }
}
