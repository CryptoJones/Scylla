//! The renderer: paint an [`App`] into a `ratatui` frame. Deliberately thin and stateless — it reads
//! the `App`'s projection and draws it; it holds no logic the conformance tests would pin. Two
//! screens: the **navigator** (a one-line title, a function list | detail split, a status bar) and
//! the **diff** (a summary line + a list of color-coded changes), toggled by `App::screen`.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, DiffKind, Mode, Screen};

pub fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Title bar.
    let title = Line::from(vec![
        Span::styled(" scylla-tui ", Style::new().bold().reversed()),
        Span::raw(format!(
            "  {} [{}] — {} functions",
            app.program_name(),
            app.language(),
            app.function_count()
        )),
    ]);
    f.render_widget(Paragraph::new(title), rows[0]);

    match app.screen() {
        Screen::Functions => draw_functions(f, app, rows[1]),
        Screen::Diff => draw_diff(f, app, rows[1]),
    }

    // Status / keybind bar.
    let status: String = match app.screen() {
        Screen::Functions => match app.mode {
            Mode::Browse => {
                let diff_hint = if app.has_diff() { " · d diff" } else { "" };
                format!("  j/k or ↑/↓ move · g/G top/bottom · / search{diff_hint} · q quit  ")
            }
            Mode::Search => "  type to filter · Enter apply · Esc clear & exit search  ".to_string(),
        },
        Screen::Diff => "  j/k or ↑/↓ move · g/G top/bottom · d/Tab back · q quit  ".to_string(),
    };
    f.render_widget(
        Paragraph::new(Span::styled(status, Style::new().reversed())),
        rows[2],
    );
}

/// The navigator: function list (left) | detail pane (right).
fn draw_functions(f: &mut Frame, app: &App, area: Rect) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let items: Vec<ListItem> = app
        .visible()
        .iter()
        .map(|fv| ListItem::new(fv.name.clone()))
        .collect();
    let list_title = if app.filter.is_empty() {
        format!("functions ({})", app.visible().len())
    } else {
        format!("functions  /{} ({})", app.filter, app.visible().len())
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(list_title))
        .highlight_style(Style::new().reversed())
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.visible().is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, body[0], &mut state);

    f.render_widget(
        Paragraph::new(detail(app))
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("function")),
        body[1],
    );
}

/// The diff screen: a summary line over a list of color-coded changes.
fn draw_diff(f: &mut Frame, app: &App, area: Rect) {
    let Some(d) = app.diff_data() else {
        f.render_widget(Paragraph::new("  (no diff loaded)"), area);
        return;
    };
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);

    let summary = Line::from(vec![
        Span::raw(format!("  {} unchanged · ", d.matched)),
        Span::styled(format!("{} renamed", d.renamed), Style::new().yellow()),
        Span::raw(" · "),
        Span::styled(format!("{} modified", d.modified), Style::new().cyan()),
        Span::raw(" · "),
        Span::styled(format!("{} added", d.added), Style::new().green()),
        Span::raw(" · "),
        Span::styled(format!("{} removed", d.removed), Style::new().red()),
    ]);
    f.render_widget(Paragraph::new(summary), parts[0]);

    let items: Vec<ListItem> = d
        .rows
        .iter()
        .map(|r| {
            let (tag, color) = match r.kind {
                DiffKind::Renamed => ("~", Color::Yellow),
                DiffKind::Modified => ("M", Color::Cyan),
                DiffKind::Added => ("+", Color::Green),
                DiffKind::Removed => ("-", Color::Red),
            };
            let line = Line::from(vec![
                Span::styled(format!(" {tag} "), Style::new().fg(color).bold()),
                Span::raw(r.name.clone()),
                Span::styled(format!("  {}", r.detail), Style::new().dim()),
            ]);
            ListItem::new(line)
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("diff ({} changes)", d.rows.len())),
        )
        .highlight_style(Style::new().reversed())
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !d.rows.is_empty() {
        state.select(Some(app.diff_selected()));
    }
    f.render_stateful_widget(list, parts[1], &mut state);
}

/// The detail pane's text for the highlighted function (its `view` at `DETAIL` + its `callers`).
fn detail(app: &App) -> Text<'static> {
    let Some(v) = app.selected_view() else {
        return Text::from("  (no function selected)");
    };
    let dash = |s: &str| if s.is_empty() { "—".to_string() } else { s.to_string() };
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(v.name.clone(), Style::new().bold())),
        Line::raw(v.summary.clone()),
        Line::raw(""),
    ];
    if let Some(addr) = v.addr {
        lines.push(Line::raw(format!("addr     0x{addr:x}")));
    }
    if let Some(bb) = v.bb_count {
        lines.push(Line::raw(format!("blocks   {bb}")));
    }
    if let Some(size) = v.size {
        lines.push(Line::raw(format!("size     {size} bytes")));
    }
    if let Some(callees) = &v.callees {
        lines.push(Line::raw(format!("callees  {}", dash(&callees.join(", ")))));
    }
    lines.push(Line::raw(format!(
        "callers  {}",
        dash(&app.selected_callers().join(", "))
    )));
    Text::from(lines)
}
