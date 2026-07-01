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
use scylla_tui::app::{App, Mode, Screen};
use scylla_tui::ui;

const USAGE: &str =
    "usage: scylla-tui <artifact.scylla> [other.scylla]   (a 2nd artifact enables the diff pane: press d)";

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if path == "-h" || path == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let session = match load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-tui: {e}");
            return ExitCode::FAILURE;
        }
    };

    // An optional second artifact enables the diff pane (toggled with `d` / Tab).
    let app = match std::env::args().nth(2) {
        Some(other_path) => match load(&other_path) {
            Ok(other) => App::with_diff(session, other),
            Err(e) => {
                eprintln!("scylla-tui: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => App::new(session),
    };

    match run(app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scylla-tui: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Load a `.scylla` artifact into a session, mapping IO/decode failures to a printable message.
fn load(path: &str) -> Result<Session, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    Session::from_artifact(&bytes).map_err(|e| format!("cannot load {path}: {e}"))
}

/// Set up the alternate-screen raw-mode terminal, run the event loop, and ALWAYS restore the
/// terminal afterwards (even if the loop errored) — a TUI that leaves the shell wedged is a bug.
fn run(mut app: App) -> io::Result<()> {
    // Restore the terminal even on a PANIC: unwinding skips the sequential teardown below, so a crash
    // in draw/handle_key would otherwise leave the user's shell in raw mode on the alternate screen.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let outcome = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let _ = std::panic::take_hook(); // drop our hook now that the terminal is restored
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
            KeyCode::Char('d') | KeyCode::Tab => app.toggle_screen(),
            KeyCode::Char('/') if app.screen() == Screen::Functions => app.enter_search(),
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
