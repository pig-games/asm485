// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn route_layout_directive_ast(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Option<LineStatus> {
        match directive {
            "DSECTION" => Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".dsection has been removed; use .place/.pack with .output",
                None,
            )),
            "REGION" => Some(self.region_directive_ast(operands)),
            "SECTION" => Some(self.section_directive_ast(operands)),
            "ENDSECTION" => Some(self.endsection_directive_ast(operands)),
            _ => None,
        }
    }

    pub(crate) fn region_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() < 3 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .region <name>, <start>, <end> [, align=<n>]",
                None,
            );
        }
        let Some(name) = operands.first().and_then(expr_to_ident) else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Invalid region name for .region",
                None,
            );
        };

        let start = match self.eval_expr_for_data_directive(&operands[1]) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        if let Err(err) = self.validate_program_address(start, ".region", expr_span(&operands[1])) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        let end = match self.eval_expr_for_data_directive(&operands[2]) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        if let Err(err) = self.validate_program_address(end, ".region", expr_span(&operands[2])) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        if start > end {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Invalid .region range",
                Some(&name),
            );
        }

        let mut align: u32 = 1;
        for expr in &operands[3..] {
            let Expr::Binary {
                op: asm_parser::BinaryOp::Eq,
                left,
                right,
                span,
            } = expr
            else {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Expected region option in key=value form",
                    None,
                    expr_span(expr),
                );
            };
            let key = match left.as_ref() {
                Expr::Identifier(name, _) | Expr::Register(name, _) => name,
                _ => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid region option key",
                        None,
                        *span,
                    )
                }
            };
            if !key.eq_ignore_ascii_case("align") {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Unknown region option key",
                    Some(key),
                    *span,
                );
            }
            let value = match self.eval_expr_for_data_directive(right) {
                Ok(value) => value,
                Err(err) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        err.error.kind(),
                        err.error.message(),
                        None,
                        err.span,
                    )
                }
            };
            if value == 0 {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Region align must be greater than zero",
                    None,
                    *span,
                );
            }
            align = value;
        }

        if let Some(existing) = self.layout.regions.get(&name) {
            if existing.start != start || existing.end != end || existing.align != align {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Region conflicts with existing definition",
                    Some(&name),
                );
            }
        } else {
            if let Some((other_name, overlap_start, overlap_end)) = self
                .layout
                .regions
                .iter()
                .find_map(|(existing_name, existing)| {
                    if start <= existing.end && existing.start <= end {
                        Some((
                            existing_name,
                            start.max(existing.start),
                            end.min(existing.end),
                        ))
                    } else {
                        None
                    }
                })
            {
                let msg = format!(
                    "Region range overlaps existing region '{other_name}' at ${}..${}",
                    super::format_addr(overlap_start),
                    super::format_addr(overlap_end)
                );
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &msg,
                    Some(&name),
                );
            }
            self.layout.regions.insert(
                name.clone(),
                RegionState {
                    name,
                    start,
                    end,
                    cursor: start,
                    align,
                    placed: Vec::new(),
                },
            );
        }
        LineStatus::Ok
    }

    pub(crate) fn section_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing section name for .section",
                None,
            );
        }
        let Some(name) = operands.first().and_then(expr_to_ident) else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Invalid section name for .section",
                None,
            );
        };
        let options = match self.parse_section_options(&operands[1..]) {
            Ok(options) => options,
            Err(status) => return status,
        };
        if let Some(section) = self.layout.sections.get_mut(&name) {
            if section.align == 0 {
                section.align = 1;
            }
        }
        if let Some(section) = self.layout.sections.get(&name) {
            if section.emitted {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Section has already been placed",
                    Some(&name),
                );
            }
            if let Some(align) = options.align {
                if section.align != align {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section align conflicts with existing definition",
                        Some(&name),
                    );
                }
            }
            if let Some(kind) = options.kind {
                if section.kind != kind {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section kind conflicts with existing definition",
                        Some(&name),
                    );
                }
            }
            if let Some(region) = options.region.as_deref() {
                if section.default_region.as_deref() != Some(region) {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section region conflicts with existing definition",
                        Some(&name),
                    );
                }
            }
        } else {
            let mut section = SectionState {
                align: 1,
                ..SectionState::default()
            };
            if let Some(align) = options.align {
                section.align = align;
            }
            if let Some(kind) = options.kind {
                section.kind = kind;
            }
            section.default_region = options.region;
            self.layout.sections.insert(name.clone(), section);
        }
        self.layout
            .section_stack
            .push(self.layout.current_section.take());
        self.layout.current_section = Some(name);
        LineStatus::Ok
    }

    pub(crate) fn endsection_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unexpected operands for .endsection",
                None,
            );
        }
        if !self.in_section() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".endsection found without matching .section",
                None,
            );
        }
        self.layout.current_section = self.layout.section_stack.pop().unwrap_or(None);
        LineStatus::Ok
    }

    pub(crate) fn parse_section_kind_expr(&self, expr: &Expr) -> Option<SectionKind> {
        let text = match expr {
            Expr::Identifier(text, _) | Expr::Register(text, _) | Expr::Number(text, _) => {
                text.as_str()
            }
            Expr::String(bytes, _) => std::str::from_utf8(bytes).ok()?,
            _ => return None,
        };
        if text.eq_ignore_ascii_case("code") {
            Some(SectionKind::Code)
        } else if text.eq_ignore_ascii_case("data") {
            Some(SectionKind::Data)
        } else if text.eq_ignore_ascii_case("bss") {
            Some(SectionKind::Bss)
        } else {
            None
        }
    }

    pub(crate) fn parse_section_options(
        &mut self,
        operands: &[Expr],
    ) -> Result<SectionOptions, LineStatus> {
        let mut options = SectionOptions::default();
        for option in operands {
            let Expr::Binary {
                op: asm_parser::BinaryOp::Eq,
                left,
                right,
                span,
            } = option
            else {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Expected section option in key=value form",
                    None,
                    expr_span(option),
                ));
            };
            let key = match left.as_ref() {
                Expr::Identifier(name, _) | Expr::Register(name, _) => name,
                _ => {
                    return Err(self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid section option key",
                        None,
                        *span,
                    ))
                }
            };

            if key.eq_ignore_ascii_case("align") {
                let align = match self.eval_expr_for_data_directive(right) {
                    Ok(value) => value,
                    Err(err) => {
                        return Err(self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        ))
                    }
                };
                if align == 0 {
                    return Err(self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section align must be greater than zero",
                        None,
                        *span,
                    ));
                }
                options.align = Some(align);
                continue;
            }

            if key.eq_ignore_ascii_case("kind") {
                let kind = match self.parse_section_kind_expr(right) {
                    Some(kind) => kind,
                    None => {
                        return Err(self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section kind must be code, data, or bss",
                            None,
                            *span,
                        ))
                    }
                };
                options.kind = Some(kind);
                continue;
            }

            if key.eq_ignore_ascii_case("region") {
                let region = match right.as_ref() {
                    Expr::Identifier(name, _) | Expr::Register(name, _) => name.clone(),
                    Expr::String(bytes, _) => String::from_utf8_lossy(bytes).to_string(),
                    _ => {
                        return Err(self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section region must be an identifier or string",
                            None,
                            *span,
                        ))
                    }
                };
                options.region = Some(region);
                continue;
            }

            return Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unknown section option key",
                Some(key),
                *span,
            ));
        }
        Ok(options)
    }

    pub(crate) fn align_up(value: u32, align: u32) -> Option<u32> {
        if align <= 1 {
            return Some(value);
        }
        let rem = value % align;
        if rem == 0 {
            Some(value)
        } else {
            value.checked_add(align - rem)
        }
    }

    pub(crate) fn place_section_in_region(
        &mut self,
        section_name: &str,
        region_name: &str,
        directive_align: Option<u32>,
        span: Span,
    ) -> LineStatus {
        if self.in_section() {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".place/.pack is not allowed inside an active .section block",
                None,
                span,
            );
        }

        let (section_align, section_size, section_placed, section_default_region) =
            match self.layout.sections.get(section_name) {
                Some(section) => (
                    section.align.max(1),
                    section.size_bytes(),
                    section.layout_placed,
                    section.default_region.clone(),
                ),
                None => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unknown section in placement directive",
                        Some(section_name),
                        span,
                    )
                }
            };
        if section_placed {
            if self.pass > 1 {
                return LineStatus::Ok;
            }
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section has already been placed",
                Some(section_name),
                span,
            );
        }
        if let Some(bound_region) = section_default_region {
            if !bound_region.eq_ignore_ascii_case(region_name) {
                let msg = format!(
                    "Section is bound to region '{bound_region}' but was placed in region '{region_name}'"
                );
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &msg,
                    Some(section_name),
                    span,
                );
            }
        }

        let (region_align, region_cursor, region_end) = match self.layout.regions.get(region_name) {
            Some(region) => (region.align.max(1), region.cursor, region.end),
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Unknown region in placement directive",
                    Some(region_name),
                    span,
                )
            }
        };

        let align = directive_align
            .unwrap_or(1)
            .max(region_align)
            .max(section_align);
        let base = match Self::align_up(region_cursor, align) {
            Some(base) => base,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Section alignment overflows address range",
                    Some(section_name),
                    span,
                )
            }
        };
        if let Err(err) = self.validate_program_address(base, ".place/.pack", span) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                Some(section_name),
                err.span,
            );
        }
        let size = section_size;
        let last_addr = if size == 0 {
            base
        } else {
            match base.checked_add(size - 1) {
                Some(last_addr) => last_addr,
                None => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section placement overflows address range",
                        Some(section_name),
                        span,
                    )
                }
            }
        };
        if size > 0 {
            if let Err(err) = self.validate_program_address(last_addr, ".place/.pack", span) {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    Some(section_name),
                    err.span,
                );
            }
        }
        if size > 0 && last_addr > region_end {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section placement overflows region",
                Some(section_name),
                span,
            );
        }
        let new_cursor = match base.checked_add(size) {
            Some(new_cursor) => new_cursor,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Section placement overflows address range",
                    Some(section_name),
                    span,
                )
            }
        };
        if u64::from(new_cursor) > (u64::from(region_end) + 1) {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section placement overflows region",
                Some(section_name),
                span,
            );
        }

        if let Some(region) = self.layout.regions.get_mut(region_name) {
            region.cursor = new_cursor;
            region.placed.push(PlacedSectionInfo {
                name: section_name.to_string(),
                base,
                size: section_size,
            });
        }
        if let Some(section) = self.layout.sections.get_mut(section_name) {
            section.start_pc = base;
            section.base_addr = Some(base);
            section.layout_placed = true;
        }
        LineStatus::Ok
    }

    pub(crate) fn process_place_ast(
        &mut self,
        section: &str,
        region: &str,
        align_expr: Option<&Expr>,
        span: Span,
    ) -> LineStatus {
        let directive_align = if let Some(expr) = align_expr {
            let value = match self.eval_expr_for_data_directive(expr) {
                Ok(value) => value,
                Err(err) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        err.error.kind(),
                        err.error.message(),
                        None,
                        err.span,
                    )
                }
            };
            if value == 0 {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Placement align must be greater than zero",
                    None,
                    span,
                );
            }
            Some(value)
        } else {
            None
        };
        if self.pass == 1 {
            self.layout
                .placement_directives
                .push(PlacementDirective::Place {
                    section: section.to_string(),
                    region: region.to_string(),
                    align: directive_align,
                    span,
                });
            return LineStatus::Ok;
        }
        self.place_section_in_region(section, region, directive_align, span)
    }

    pub(crate) fn process_pack_ast(
        &mut self,
        region: &str,
        sections: &[String],
        span: Span,
    ) -> LineStatus {
        if self.pass == 1 {
            self.layout
                .placement_directives
                .push(PlacementDirective::Pack {
                    region: region.to_string(),
                    sections: sections.to_vec(),
                    span,
                });
            return LineStatus::Ok;
        }
        for section in sections {
            let status = self.place_section_in_region(section, region, None, span);
            if status == LineStatus::Error || status == LineStatus::Pass1Error {
                return status;
            }
        }
        LineStatus::Ok
    }

    pub(crate) fn apply_placement_directive(
        &mut self,
        directive: &PlacementDirective,
    ) -> LineStatus {
        match directive {
            PlacementDirective::Place {
                section,
                region,
                align,
                span,
            } => self.place_section_in_region(section, region, *align, *span),
            PlacementDirective::Pack {
                region,
                sections,
                span,
            } => {
                for section in sections {
                    let status = self.place_section_in_region(section, region, None, *span);
                    if status == LineStatus::Error || status == LineStatus::Pass1Error {
                        return status;
                    }
                }
                LineStatus::Ok
            }
        }
    }
}
