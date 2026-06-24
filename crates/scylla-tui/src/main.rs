//! `scylla-tui <artifact.scylla>` — a TUI head (DD-017): an interactive terminal navigator over a
//! `.scylla` model. Browse the function list, watch the detail pane (address, basic blocks, size,
//! callees, callers) follow the selection, and filter live with `/`. The whole thing is a thin
//! crossterm shell around `scylla_tui::app::App` — this file only sets up/tears down the terminal
//! and translates keystrokes into `App` calls; all the data comes from the client port, via `App`.
//!
//!   j / k  or  ↑ / ↓   move    g / G   top / bottom    /   search    q   quit
//!   (search mode)  type to filter · Enter apply · Esc clear & exit

use std::io;
use std::process::ExitCode;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::execute;
use ratatui::prelude::*;

use scylla_port::Session;
use scylla_tui::app::{App, Mode};
use scylla_tui::ui;

const USAGE: &str = "usage: scylla-tui <artifact.scylla>";

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if path == "-h" || path == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-tui: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let session = match Session::from_artifact(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-tui: cannot load {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    match run(App::new(session)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scylla-tui: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Set up the alternate-screen raw-mode terminal, run the event loop, and ALWAYS restore the
/// terminal afterwards (even if the loop errored) — a TUI that leaves the shell wedged is a bug.
fn run(mut app: App) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let outcome = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    outcome
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        // Poll so a resize repaints promptly even without a keystroke.
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code);
                }
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Translate one keypress into an `App` call — the only place crossterm meets the model.
fn handle_key(app: &mut App, code: KeyCode) {
    match app.mode {
        Mode::Browse => match code {
            KeyCode::Char('q') => app.quit(),
            KeyCode::Char('j') | KeyCode::Down => app.down(),
            KeyCode::Char('k') | KeyCode::Up => app.up(),
            KeyCode::Char('g') | KeyCode::Home => app.top(),
            KeyCode::Char('G') | KeyCode::End => app.bottom(),
            KeyCode::Char('/') => app.enter_search(),
            _ => {}
        },
        Mode::Search => match code {
            KeyCode::Esc => {
                app.clear_filter();
                app.leave_search();
            }
            KeyCode::Enter => app.leave_search(),
            KeyCode::Backspace => app.pop_filter(),
            KeyCode::Char(c) => app.push_filter(c),
            _ => {}
        },
    }
}
