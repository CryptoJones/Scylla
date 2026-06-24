//! The `App`: the resident session + the interaction state, and NOTHING about terminals. Every
//! method that returns data is a thin projection of a client-port verb — the browse list is
//! `Session::functions`, a live filter is `Session::search`, the detail pane is `Session::view` at
//! `DETAIL`, the callers line is `Session::callers`. That separation is the whole point: the head
//! carries no domain logic, so the conformance tests pin these methods to the port without ever
//! opening a terminal. The crossterm key layer lives in `main.rs` and only ever calls the mutators
//! below — it never reaches past this type into the port.

use scylla_model::StableId;
use scylla_port::{FunctionView, Session, Zoom};

/// What the keystrokes mean right now: navigating the list, or typing into the search filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Browse,
    Search,
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
        };
        app.recompute();
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

    // --- mutators (what the key layer drives) ---

    pub fn down(&mut self) {
        if self.selected + 1 < self.visible.len() {
            self.selected += 1;
        }
    }
    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
    pub fn top(&mut self) {
        self.selected = 0;
    }
    pub fn bottom(&mut self) {
        self.selected = self.visible.len().saturating_sub(1);
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

#[cfg(test)]
mod tests {
    use super::*;

    const ARTIFACT: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/mathlib.scylla");

    fn load() -> Session {
        Session::from_artifact(&std::fs::read(ARTIFACT).expect("read")).expect("load")
    }

    #[test]
    fn navigation_clamps_at_both_ends() {
        let mut app = App::new(load());
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
        let mut app = App::new(load());
        let full = app.visible().len();
        app.push_filter('g');
        app.push_filter('c');
        app.push_filter('d');
        assert!(app.visible().len() <= full);
        app.clear_filter();
        assert_eq!(app.visible().len(), full, "clearing the filter is lossless");
    }
}
