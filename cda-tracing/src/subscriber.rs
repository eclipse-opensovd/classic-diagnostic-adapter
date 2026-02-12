/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use nu_ansi_term::{Color, Style};
use tracing::{Event, Level, Subscriber, field::Visit};
use tracing_subscriber::{
    field::VisitOutput as _,
    fmt::{
        FmtContext, FormattedFields,
        format::{DefaultVisitor, FormatEvent, FormatFields, Writer},
        time::{ChronoUtc, FormatTime},
    },
    registry::LookupSpan,
};

macro_rules! write_colored {
        ($writer:expr, $color_support:expr, $style:expr, $($arg:tt)*) => {
            if $color_support {
                write!($writer, "{}", $style.prefix())?;
            }
            write!($writer, "{}", format_args!($($arg)*))?;
            if $color_support {
                write!($writer, "{}", $style.suffix())?;
            }
        };
    }
macro_rules! write_colored_fn {
    ($writer:expr, $color_support:expr, $style:expr, $writer_fn:expr) => {
        if $color_support {
            write!($writer, "{}", $style.prefix())?;
        }
        $writer_fn?;
        if $color_support {
            write!($writer, "{}", $style.suffix())?;
        }
    };
}

pub struct CdaFormatter {
    timer: ChronoUtc,
    nested_context_fields: bool,
    colored: bool,
    span_id: bool,
}

impl<S, N> FormatEvent<S, N> for CdaFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let colored = self.colored && writer.has_ansi_escapes();

        let meta = event.metadata();

        let dimmed_style = Style::new().dimmed();
        let lvl_style = CdaFormatter::style_for(*meta.level());
        let bold_style = Style::new().bold();

        write_colored_fn!(writer, colored, dimmed_style, self.write_time(&mut writer));
        writer.write_char(' ')?;

        if self.span_id
            && let Some(span) = event
                .parent()
                .and_then(|id| ctx.span(id))
                .or_else(|| ctx.lookup_current())
        {
            write!(writer, "[span_id={}] ", span.id().into_u64())?;
        }

        write_colored!(writer, colored, lvl_style, "{}", meta.level());

        write_colored!(writer, colored, dimmed_style, " in ");
        if meta.name() != "log event"
            && !(meta.name().starts_with("event cda-") && meta.name().contains("/src/"))
        {
            write_colored!(writer, colored, bold_style, "{}", meta.name());
        } else {
            write_colored!(writer, colored, bold_style, "{}", meta.target());
        }

        write_colored!(writer, colored, dimmed_style, " msg: ");

        let mut v = DefaultVisitor::new(writer.by_ref(), true);
        event.record(&mut v);
        v.finish()?;

        writer.write_char('\n')?;

        let scopes = event
            .parent()
            .and_then(|parent_id| ctx.span(parent_id))
            .or_else(|| ctx.lookup_current())
            .into_iter()
            .flat_map(|span| span.scope());

        for span in scopes {
            let span_meta = span.metadata();
            let same_span = span_meta.target() == meta.target() && span_meta.name() == meta.name();

            if !same_span {
                // only output context for different spans
                write_colored!(writer, colored, dimmed_style, "    in ");
                if self.span_id {
                    write!(writer, "[span_id={}] ", span.id().into_u64())?;
                }
                write!(writer, "{}::", span_meta.target())?;
                write_colored!(writer, colored, bold_style, "{}", span_meta.name(),);

                if !self.nested_context_fields {
                    writer.write_char('\n')?;
                    continue;
                }
            }

            if self.nested_context_fields || same_span {
                let ext = span.extensions();
                if let Some(fields) = &ext.get::<FormattedFields<N>>()
                    && !fields.is_empty()
                {
                    if same_span {
                        write!(writer, "   ")?;
                    }
                    write_colored!(writer, colored, dimmed_style, " with ");
                    let fields = format!("{fields}");
                    for field in fields.split_whitespace().collect::<HashSet<_>>() {
                        write!(writer, "{field} ")?;
                    }
                    writer.write_char('\n')?;
                }
            }
        }

        Ok(())
    }
}

impl CdaFormatter {
    #[must_use]
    pub fn new(timer: ChronoUtc) -> Self {
        CdaFormatter {
            timer,
            nested_context_fields: true,
            colored: true,
            span_id: true,
        }
    }

    #[must_use]
    pub fn with_nested_context_fields(mut self, nexted_context_fields_enabled: bool) -> Self {
        self.nested_context_fields = nexted_context_fields_enabled;
        self
    }

    #[must_use]
    pub fn with_color(mut self, colored: bool) -> Self {
        self.colored = colored;
        self
    }

    #[must_use]
    pub fn with_span_id(mut self, span_id: bool) -> Self {
        self.span_id = span_id;
        self
    }

    fn style_for(level: Level) -> Style {
        match level {
            Level::TRACE => Style::new().fg(Color::Purple),
            Level::DEBUG => Style::new().fg(Color::Blue),
            Level::INFO => Style::new().fg(Color::Green),
            Level::WARN => Style::new().fg(Color::Yellow),
            Level::ERROR => Style::new().fg(Color::Red),
        }
    }

    fn write_time(&self, writer: &mut Writer<'_>) -> std::fmt::Result {
        if self.timer.format_time(writer).is_err() {
            writer.write_str("<time unknown>")?;
        }
        Ok(())
    }
}

pub struct FieldVisitor<'a> {
    fields: &'a mut HashMap<String, String>,
}

impl Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let e = self.fields.entry(field.name().to_owned()).or_default();
        *e = format!("{value:?}");
    }
}

/// Creates a file log writer that writes to the specified directory and file name.
/// If `append` is true, it appends to the file; otherwise, it truncates the file.
///
/// # Errors
/// Returns `Err` if the directory cannot be created or the file cannot be opened.
pub fn file_log_writer(
    dir: impl AsRef<Path>,
    file_name: impl AsRef<Path>,
    append: bool,
) -> Result<impl std::io::Write, String> {
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create log file dir: {e:?}"))?;

    let file_path = dir.as_ref().join(file_name);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(file_path)
        .map_err(|e| format!("Failed to open log file: {e:?}"))?;

    Ok(strip_ansi_escapes::Writer::new(file))
}
