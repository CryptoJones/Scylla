//! The `App`: the resident session + the interaction state, and NOTHING about terminals. Every
//! method that returns data is a thin projection of a client-port verb — the browse list is
//! `Session::functions`, a live filter is `Session::search`, the detail pane is `Session::view` at
//! `DETAIL`, the callers line is `Session::callers`, and (when a second artifact is loaded) the diff
//! pane is `Session::diff`. That separation is the whole point: the head carries no domain logic, so
//! the conformance tests pin these methods to the port without ever opening a terminal. The crossterm
//! key layer lives in `main.rs` and only ever calls the mutators below — it never reaches past this
//! type into the port.

use std::collections::HashMap;

use scylla_model::StableId;
use scylla_port::{FunctionView, MatchInfo, Session, Zoom};

/// What the keystrokes mean right now: navigating the list, or typing into the search filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Browse,
    Search,
}

/// Which pane is up: the function navigator, or the structural diff (only reachable when a second
/// artifact was loaded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Functions,
    Diff,
}

/// The classification of one diff row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Renamed,
    Modified,
    Added,
    Removed,
}

/// One renderable diff row: a kind, the function name, and a trailing annotation (the new name
/// and/or the recovery rung + confidence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffRow {
    pub kind: DiffKind,
    pub name: String,
    pub detail: String,
}

/// The precomputed structural diff: the interesting rows (renamed / modified / added / removed) plus
/// the summary counts. Matched-but-unchanged pairs are a COUNT, not rows — there's nothing to look
/// at — so `rows.len() == renamed + modified + added + removed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiffData {
    pub rows: Vec<DiffRow>,
    pub matched: usize,
    pub renamed: usize,
    pub modified: usize,
    pub added: usize,
    pub removed: usize,
}

pub struct App {
    session: Session,
    /// The currently-visible function list (all functions, or the search hits), sorted by name.
    /// Recomputed only when the filter changes — navigation is pure index movement over this.
    visible: Vec<FunctionView>,
    /// Index into `visible` of the highlighted function.
    pub selected: usize,
    pub mode: Mode,
    /// The live search query; empty means "show everything".
    pub filter: String,
    pub should_quit: bool,
    /// The structural diff against a second artifact, if one was loaded; `None` = navigator only.
    diff: Option<DiffData>,
    /// Which pane is showing.
    screen: Screen,
    /// Selection within the diff pane.
    diff_selected: usize,
}

impl App {
    pub fn new(session: Session) -> Self {
        let mut app = App {
            session,
            visible: Vec::new(),
            selected: 0,
            mode: Mode::Browse,
            filter: String::new(),
            should_quit: false,
            diff: None,
            screen: Screen::Functions,
            diff_selected: 0,
        };
        app.recompute();
        app
    }

    /// Open with a second artifact loaded for diffing — the `d` key then toggles a structural-diff
    /// pane (DD-017). The navigator behaves exactly as in [`App::new`]; the diff is precomputed once.
    pub fn with_diff(session: Session, other: Session) -> Self {
        let mut app = App::new(session);
        app.diff = Some(build_diff(&app.session, &other));
        app
    }

    /// Rebuild the visible list from the current filter — `functions()` when empty, `search()`
    /// otherwise — sorted by name, clamping the selection back into range.
    fn recompute(&mut self) {
        let mut v = if self.filter.is_empty() {
            self.session.functions(Zoom::Domain)
        } else {
            self.session.search(&self.filter, Zoom::Domain)
        };
        v.sort_by(|a, b| a.name.cmp(&b.name));
        self.visible = v;
        if self.selected >= self.visible.len() {
            self.selected = self.visible.len().saturating_sub(1);
        }
    }

    // --- reads (the projection the renderer paints) ---

    pub fn visible(&self) -> &[FunctionView] {
        &self.visible
    }
    pub fn program_name(&self) -> &str {
        &self.session.program().name
    }
    pub fn language(&self) -> &str {
        &self.session.program().language
    }
    pub fn function_count(&self) -> usize {
        self.session.program().functions.len()
    }

    fn selected_id(&self) -> Option<StableId> {
        self.visible.get(self.selected).map(|f| f.id)
    }

    /// The highlighted function's full view at `DETAIL` zoom — the detail pane's data.
    pub fn selected_view(&self) -> Option<FunctionView> {
        let id = self.selected_id()?;
        self.session.view(id, Zoom::Detail).ok()
    }

    /// The display names of the functions that call the highlighted one (the `callers` verb).
    pub fn selected_callers(&self) -> Vec<String> {
        let Some(id) = self.selected_id() else {
            return Vec::new();
        };
        let prog = self.session.program();
        self.session
            .callers(id)
            .into_iter()
            .filter_map(|c| prog.display_name(c))
            .collect()
    }

    // --- diff pane ---

    pub fn has_diff(&self) -> bool {
        self.diff.is_some()
    }
    pub fn screen(&self) -> Screen {
        self.screen
    }
    pub fn diff_data(&self) -> Option<&DiffData> {
        self.diff.as_ref()
    }
    pub fn diff_selected(&self) -> usize {
        self.diff_selected
    }
    fn diff_rows(&self) -> &[DiffRow] {
        self.diff.as_ref().map(|d| d.rows.as_slice()).unwrap_or(&[])
    }
    /// Flip between the navigator and the diff pane (a no-op if no second artifact was loaded).
    pub fn toggle_screen(&mut self) {
        if !self.has_diff() {
            return;
        }
        self.screen = match self.screen {
            Screen::Functions => Screen::Diff,
            Screen::Diff => Screen::Functions,
        };
    }

    // --- mutators (what the key layer drives; navigation follows the active screen) ---

    pub fn down(&mut self) {
        match self.screen {
            Screen::Functions => {
                if self.selected + 1 < self.visible.len() {
                    self.selected += 1;
                }
            }
            Screen::Diff => {
                if self.diff_selected + 1 < self.diff_rows().len() {
                    self.diff_selected += 1;
                }
            }
        }
    }
    pub fn up(&mut self) {
        match self.screen {
            Screen::Functions => self.selected = self.selected.saturating_sub(1),
            Screen::Diff => self.diff_selected = self.diff_selected.saturating_sub(1),
        }
    }
    pub fn top(&mut self) {
        match self.screen {
            Screen::Functions => self.selected = 0,
            Screen::Diff => self.diff_selected = 0,
        }
    }
    pub fn bottom(&mut self) {
        match self.screen {
            Screen::Functions => self.selected = self.visible.len().saturating_sub(1),
            Screen::Diff => self.diff_selected = self.diff_rows().len().saturating_sub(1),
        }
    }

    pub fn enter_search(&mut self) {
        self.mode = Mode::Search;
    }
    pub fn leave_search(&mut self) {
        self.mode = Mode::Browse;
    }
    pub fn push_filter(&mut self, c: char) {
        self.filter.push(c);
        self.selected = 0;
        self.recompute();
    }
    pub fn pop_filter(&mut self) {
        self.filter.pop();
        self.selected = 0;
        self.recompute();
    }
    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.selected = 0;
        self.recompute();
    }
    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

/// Fold a `Session::diff` into renderable rows + summary counts. Matched-but-unchanged pairs are
/// counted, not listed; renamed/modified pairs carry their recovery rung + confidence (the same
/// provenance every other head surfaces).
fn build_diff(this: &Session, other: &Session) -> DiffData {
    let d = this.diff(other);
    let prov: HashMap<String, MatchInfo> = d.provenance.iter().cloned().collect();
    let mut data = DiffData::default();
    for (a, b) in &d.matched {
        if a == b {
            data.matched += 1;
        } else {
            data.renamed += 1;
            let detail = match prov.get(a) {
                Some(i) => format!("→ {b}  ({} {}%)", i.method.as_str(), i.confidence),
                None => format!("→ {b}"),
            };
            data.rows.push(DiffRow {
                kind: DiffKind::Renamed,
                name: a.clone(),
                detail,
            });
        }
    }
    for (a, b) in &d.changed {
        let name = if a == b { a.clone() } else { format!("{a} → {b}") };
        let detail = prov
            .get(a)
            .map(|i| format!("({} {}%)", i.method.as_str(), i.confidence))
            .unwrap_or_default();
        data.rows.push(DiffRow {
            kind: DiffKind::Modified,
            name,
            detail,
        });
    }
    for n in &d.only_there {
        data.rows.push(DiffRow {
            kind: DiffKind::Added,
            name: n.clone(),
            detail: String::new(),
        });
    }
    for n in &d.only_here {
        data.rows.push(DiffRow {
            kind: DiffKind::Removed,
            name: n.clone(),
            detail: String::new(),
        });
    }
    data.modified = d.changed.len();
    data.added = d.only_there.len();
    data.removed = d.only_here.len();
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/");

    fn load(name: &str) -> Session {
        Session::from_artifact(&std::fs::read(format!("{DIR}{name}")).expect("read"))
            .expect("load")
    }

    #[test]
    fn navigation_clamps_at_both_ends() {
        let mut app = App::new(load("mathlib.scylla"));
        let n = app.visible().len();
        assert!(n > 1, "fixture has functions");
        app.up(); // already at top — stays
        assert_eq!(app.selected, 0);
        for _ in 0..(n + 5) {
            app.down();
        }
        assert_eq!(app.selected, n - 1, "down clamps at the last row");
        app.top();
        assert_eq!(app.selected, 0);
        app.bottom();
        assert_eq!(app.selected, n - 1);
    }

    #[test]
    fn clearing_the_filter_restores_the_full_list() {
        let mut app = App::new(load("mathlib.scylla"));
        let full = app.visible().len();
        app.push_filter('g');
        app.push_filter('c');
        app.push_filter('d');
        assert!(app.visible().len() <= full);
        app.clear_filter();
        assert_eq!(app.visible().len(), full, "clearing the filter is lossless");
    }

    #[test]
    fn no_diff_means_the_toggle_is_inert() {
        let mut app = App::new(load("mathlib.scylla"));
        assert!(!app.has_diff());
        app.toggle_screen();
        assert_eq!(app.screen(), Screen::Functions, "no second artifact → no diff pane");
        assert!(app.diff_data().is_none());
    }

    #[test]
    fn diff_pane_matches_the_ports_diff() {
        let app = App::with_diff(load("mathlib.scylla"), load("mathlib_patched.scylla"));
        let d = app.diff_data().expect("diff present");

        // Counts equal the port's diff() against the patched build.
        let p = load("mathlib.scylla");
        let pd = p.diff(&load("mathlib_patched.scylla"));
        let renamed = pd.matched.iter().filter(|(a, b)| a != b).count();
        assert_eq!(d.matched, pd.matched.len() - renamed, "matched-unchanged count");
        assert_eq!(d.renamed, renamed, "renamed count");
        assert_eq!(d.modified, pd.changed.len(), "modified count");
        assert_eq!(d.added, pd.only_there.len(), "added count");
        assert_eq!(d.removed, pd.only_here.len(), "removed count");
        // The rows are exactly the interesting changes — matched-unchanged are not listed.
        assert_eq!(
            d.rows.len(),
            d.renamed + d.modified + d.added + d.removed,
            "rows are the interesting changes only"
        );
    }
}
