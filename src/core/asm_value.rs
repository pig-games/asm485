// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Assembly-time compound value model.
//!
//! This module introduces non-scalar value shapes used by upcoming repetition
//! and struct features while preserving the legacy scalar path.

use std::collections::HashMap;

/// Assembly-time value representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsmValue {
    /// Single scalar value.
    Scalar(i64),
    /// Normalized range with exclusive end.
    Range { start: i64, end: i64, step: i64 },
    /// Materialized list of scalar values.
    List(Vec<i64>),
    /// Struct layout definition.
    Struct(StructDef),
    /// Struct instance value (field name -> scalar value).
    StructInstance(StructInstance),
}

/// Struct definition metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<StructField>,
    pub size: u32,
}

/// Single struct field metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructField {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

/// Struct instance value with concrete field payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructInstance {
    pub type_name: String,
    pub fields: HashMap<String, i64>,
}

/// Construction/evaluation errors for [`AsmValue`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsmValueError {
    ZeroStep,
    EndOverflow,
    DirectionMismatch { start: i64, end: i64, step: i64 },
}

/// Iterator over list/range values.
pub enum AsmValueIter<'a> {
    List(std::iter::Copied<std::slice::Iter<'a, i64>>),
    Range {
        current: i64,
        end: i64,
        step: i64,
        done: bool,
    },
}

impl<'a> Iterator for AsmValueIter<'a> {
    type Item = i64;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AsmValueIter::List(iter) => iter.next(),
            AsmValueIter::Range {
                current,
                end,
                step,
                done,
            } => {
                if *done {
                    return None;
                }
                let in_bounds = if *step > 0 {
                    *current < *end
                } else {
                    *current > *end
                };
                if !in_bounds {
                    *done = true;
                    return None;
                }
                let value = *current;
                *current = current.saturating_add(*step);
                Some(value)
            }
        }
    }
}

impl AsmValue {
    pub fn scalar(value: i64) -> Self {
        Self::Scalar(value)
    }

    /// Build a normalized range from source syntax parts.
    pub fn try_range(
        start: i64,
        end: i64,
        inclusive: bool,
        step: Option<i64>,
    ) -> Result<Self, AsmValueError> {
        let step = step.unwrap_or(if start <= end { 1 } else { -1 });
        if step == 0 {
            return Err(AsmValueError::ZeroStep);
        }
        let normalized_end = if inclusive {
            end.checked_add(step.signum())
                .ok_or(AsmValueError::EndOverflow)?
        } else {
            end
        };
        if (step > 0 && start > normalized_end) || (step < 0 && start < normalized_end) {
            return Err(AsmValueError::DirectionMismatch { start, end, step });
        }
        Ok(Self::Range {
            start,
            end: normalized_end,
            step,
        })
    }

    pub fn as_scalar(&self) -> Option<i64> {
        match self {
            AsmValue::Scalar(value) => Some(*value),
            _ => None,
        }
    }

    pub fn len(&self) -> Option<usize> {
        match self {
            AsmValue::Scalar(_) | AsmValue::Struct(_) | AsmValue::StructInstance(_) => None,
            AsmValue::List(items) => Some(items.len()),
            AsmValue::Range { start, end, step } => Some(range_len(*start, *end, *step)),
        }
    }

    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|len| len == 0)
    }

    pub fn iter(&self) -> Option<AsmValueIter<'_>> {
        match self {
            AsmValue::Scalar(_) | AsmValue::Struct(_) | AsmValue::StructInstance(_) => None,
            AsmValue::List(items) => Some(AsmValueIter::List(items.iter().copied())),
            AsmValue::Range { start, end, step } => Some(AsmValueIter::Range {
                current: *start,
                end: *end,
                step: *step,
                done: false,
            }),
        }
    }

    pub fn get(&self, index: usize) -> Option<i64> {
        match self {
            AsmValue::Scalar(_) | AsmValue::Struct(_) | AsmValue::StructInstance(_) => None,
            AsmValue::List(items) => items.get(index).copied(),
            AsmValue::Range { start, end, step } => {
                let len = range_len(*start, *end, *step);
                if index >= len {
                    return None;
                }
                let index_i64 = i64::try_from(index).ok()?;
                start.checked_add(step.checked_mul(index_i64)?)
            }
        }
    }

    pub fn to_list(&self) -> Option<Vec<i64>> {
        self.iter().map(|iter| iter.collect())
    }

    pub fn field_offset(&self, name: &str) -> Option<u32> {
        match self {
            AsmValue::Struct(def) => def
                .fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| field.offset),
            _ => None,
        }
    }

    pub fn field_value(&self, name: &str) -> Option<i64> {
        match self {
            AsmValue::StructInstance(instance) => {
                instance.fields.get(name).copied().or_else(|| {
                    let lookup = name.to_ascii_uppercase();
                    instance.fields.get(&lookup).copied()
                })
            }
            _ => None,
        }
    }
}

fn range_len(start: i64, end: i64, step: i64) -> usize {
    if step == 0 {
        return 0;
    }
    if (step > 0 && start >= end) || (step < 0 && start <= end) {
        return 0;
    }
    let step_abs = i128::from(step.abs());
    if step_abs == 0 {
        return 0;
    }
    let distance = if step > 0 {
        i128::from(end) - i128::from(start)
    } else {
        i128::from(start) - i128::from(end)
    };
    let count = ((distance - 1) / step_abs) + 1;
    usize::try_from(count).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{AsmValue, AsmValueError, StructDef, StructField, StructInstance};
    use std::collections::HashMap;

    #[test]
    fn range_construction_normalizes_inclusive_end() {
        let value = AsmValue::try_range(0, 3, true, None).expect("range should build");
        assert_eq!(
            value,
            AsmValue::Range {
                start: 0,
                end: 4,
                step: 1
            }
        );
        assert_eq!(value.to_list(), Some(vec![0, 1, 2, 3]));
    }

    #[test]
    fn descending_range_uses_negative_default_step() {
        let value = AsmValue::try_range(3, 0, true, None).expect("descending range should build");
        assert_eq!(
            value,
            AsmValue::Range {
                start: 3,
                end: -1,
                step: -1
            }
        );
        assert_eq!(value.to_list(), Some(vec![3, 2, 1, 0]));
    }

    #[test]
    fn range_rejects_zero_step_and_direction_mismatch() {
        assert_eq!(
            AsmValue::try_range(0, 10, false, Some(0)),
            Err(AsmValueError::ZeroStep)
        );
        assert_eq!(
            AsmValue::try_range(0, 10, false, Some(-1)),
            Err(AsmValueError::DirectionMismatch {
                start: 0,
                end: 10,
                step: -1
            })
        );
    }

    #[test]
    fn list_and_range_len_get_and_iter_work() {
        let list = AsmValue::List(vec![10, 20, 30]);
        assert_eq!(list.len(), Some(3));
        assert_eq!(list.get(1), Some(20));
        assert_eq!(list.get(3), None);
        assert_eq!(
            list.iter().expect("list iter").collect::<Vec<_>>(),
            vec![10, 20, 30]
        );

        let range = AsmValue::try_range(2, 10, false, Some(3)).expect("range should build");
        assert_eq!(range.len(), Some(3));
        assert_eq!(range.get(0), Some(2));
        assert_eq!(range.get(2), Some(8));
        assert_eq!(range.get(3), None);
        assert_eq!(range.to_list(), Some(vec![2, 5, 8]));
    }

    #[test]
    fn struct_field_offset_lookup_works() {
        let value = AsmValue::Struct(StructDef {
            name: "Sprite".to_string(),
            fields: vec![
                StructField {
                    name: "x".to_string(),
                    offset: 0,
                    size: 1,
                },
                StructField {
                    name: "y".to_string(),
                    offset: 1,
                    size: 1,
                },
            ],
            size: 2,
        });
        assert_eq!(value.field_offset("x"), Some(0));
        assert_eq!(value.field_offset("y"), Some(1));
        assert_eq!(value.field_offset("z"), None);
    }

    #[test]
    fn struct_instance_field_value_lookup_works() {
        let mut fields = HashMap::new();
        fields.insert("X".to_string(), 24);
        fields.insert("Y".to_string(), 50);
        let value = AsmValue::StructInstance(StructInstance {
            type_name: "Sprite".to_string(),
            fields,
        });
        assert_eq!(value.field_value("x"), Some(24));
        assert_eq!(value.field_value("Y"), Some(50));
        assert_eq!(value.field_value("color"), None);
        assert_eq!(value.len(), None);
        assert_eq!(value.get(0), None);
    }
}
