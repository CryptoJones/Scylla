//! The renderer: paint an [`App`] into a `ratatui` frame. This is deliberately thin and stateless —
//! it reads the `App`'s projection and draws it; it holds no logic the conformance tests would want
//! to pin. Layout: a one-line title, a body split into the function list (left) and the detail pane
//! (right), and a one-line status/keybind bar.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, Mode};

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

    // Body: function list | detail.
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[1]);

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

    // Status / keybind bar.
    let status = match app.mode {
        Mode::Browse => "  j/k or ↑/↓ move · g/G top/bottom · / search · q quit  ",
        Mode::Search => "  type to filter · Enter apply · Esc clear & exit search  ",
    };
    f.render_widget(
        Paragraph::new(Span::styled(status, Style::new().reversed())),
        rows[2],
    );
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
