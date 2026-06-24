//! Contract-conformance for the TUI head (DD-017): same contract as the CLI / HTTP / GraphQL heads,
//! against the `App`. The navigator is a thin projection of the client port, so the `App`'s data —
//! the browse list, the live filter, the detail view, the callers — must equal what
//! `scylla_port::Session` computes for the same artifact, verb for verb. Expectations are derived
//! from the port in-process; no frozen golden numbers and no terminal. If the head drifts from the
//! body, these fail.

use scylla_port::{Session, Zoom};
use scylla_tui::app::App;

const ARTIFACT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/mathlib.scylla");

fn load() -> Session {
    Session::from_artifact(&std::fs::read(ARTIFACT).expect("read artifact")).expect("load artifact")
}

#[test]
fn browse_list_is_the_ports_functions() {
    let app = App::new(load());
    let p = load();
    let mut expected: Vec<String> = p.functions(Zoom::Domain).into_iter().map(|f| f.name).collect();
    expected.sort();
    let got: Vec<String> = app.visible().iter().map(|f| f.name.clone()).collect();
    assert_eq!(got, expected, "the browse list is exactly the port's functions, sorted");
}

#[test]
fn live_filter_is_the_ports_search() {
    let mut app = App::new(load());
    for c in "gcd".chars() {
        app.push_filter(c);
    }
    let p = load();
    let mut expected: Vec<String> = p
        .search("gcd", Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();
    let got: Vec<String> = app.visible().iter().map(|f| f.name.clone()).collect();
    assert_eq!(got, expected, "the filtered list is exactly the port's search()");
}

#[test]
fn detail_and_callers_are_the_ports_view() {
    let mut app = App::new(load());
    // Drive the selection to gcd the way a keypress would.
    let idx = app
        .visible()
        .iter()
        .position(|f| f.name == "gcd")
        .expect("gcd present");
    for _ in 0..idx {
        app.down();
    }

    let p = load();
    let gid = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd present")
        .id;

    // The detail pane equals the port's view at DETAIL, field for field.
    assert_eq!(
        app.selected_view().expect("selected view"),
        p.view(gid, Zoom::Detail).expect("port view"),
        "the detail view equals the port's view at DETAIL"
    );

    // The callers line equals the port's callers verb, by display name.
    let prog = p.program();
    let expected_callers: Vec<String> = p
        .callers(gid)
        .into_iter()
        .filter_map(|c| prog.display_name(c))
        .collect();
    assert_eq!(
        app.selected_callers(),
        expected_callers,
        "the callers line matches the port"
    );
}
