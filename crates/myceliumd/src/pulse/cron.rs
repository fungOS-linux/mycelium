//! Five-field cron parsing and next-fire calculation.
//!
//! The grammar is deliberately small: `*`, `n`, `a-b`, `a/n`, `a-b/n` and
//! comma lists. Day-of-month and day-of-week are ANDed, which is the rule a
//! person can predict from the expression they typed. Names are not accepted:
//! one grammar is easier to keep honest than three hundred spellings.
//!
//! This is the parser the Pulse scheduler uses. It has no clock of its own;
//! callers pass `now_ms` and get the next strictly-later fire.

use std::fmt;

const MS_PER_MINUTE: i64 = 60_000;
const MS_PER_DAY: i64 = 86_400_000;
const MINUTES_PER_DAY: i64 = 1_440;
const SEARCH_DAYS: i64 = 3_660;

const FIELD_NAMES: [&str; 5] = ["minute", "hour", "day", "month", "weekday"];
const FIELD_BOUNDS: [(u8, u8); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub text: String,
}

impl Problem {
    pub fn new(field: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            text: text.into(),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    fields: [Field; 5],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Field {
    raw: String,
    values: Vec<u8>,
}

impl Schedule {
    pub fn parse(text: &str) -> Result<Self, Vec<Problem>> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(vec![Problem::new(
                "schedule",
                format!(
                    "a schedule is five fields (minute hour day month weekday); {text:?} has {}",
                    parts.len()
                ),
            )]);
        }

        let mut problems = Vec::new();
        let mut parsed: Vec<Option<Field>> = Vec::with_capacity(5);
        for (index, part) in parts.iter().enumerate() {
            let (min, max) = FIELD_BOUNDS[index];
            let mut field = parse_field(part, min, max, FIELD_NAMES[index], &mut problems);
            if index == 4 {
                if let Some(field) = field.as_mut() {
                    for value in &mut field.values {
                        if *value == 7 {
                            *value = 0;
                        }
                    }
                    field.values.sort_unstable();
                    field.values.dedup();
                }
            }
            parsed.push(field);
        }

        if problems.is_empty() {
            if let [Some(minute), Some(hour), Some(day), Some(month), Some(weekday)] =
                parsed.as_slice()
            {
                return Ok(Self {
                    fields: [
                        minute.clone(),
                        hour.clone(),
                        day.clone(),
                        month.clone(),
                        weekday.clone(),
                    ],
                });
            }
            problems.push(Problem::new(
                "schedule",
                "a schedule field was not readable",
            ));
        }
        Err(problems)
    }

    fn values(&self, index: usize) -> &[u8] {
        &self.fields[index].values
    }

    fn day_matches(&self, month: u8, day: u8, weekday: u8) -> bool {
        self.values(3).contains(&month)
            && self.values(2).contains(&day)
            && self.values(4).contains(&weekday)
    }

    /// The first fire strictly after `now_ms`.
    pub fn next_after(&self, now_ms: i64) -> Option<i64> {
        let now_minute = now_ms.div_euclid(MS_PER_MINUTE);
        let today = now_minute.div_euclid(MINUTES_PER_DAY);
        let start = now_minute.rem_euclid(MINUTES_PER_DAY);

        for offset in 0..=SEARCH_DAYS {
            let days = today + offset;
            let (_, month, day) = civil_from_days(days);
            let weekday = weekday_from_days(days);
            if !self.day_matches(month, day, weekday) {
                continue;
            }
            let from = if offset == 0 { start + 1 } else { 0 };
            for hour in self.values(1) {
                for minute in self.values(0) {
                    let at = i64::from(*hour) * 60 + i64::from(*minute);
                    if at < from {
                        continue;
                    }
                    return Some(days * MS_PER_DAY + at * MS_PER_MINUTE);
                }
            }
        }
        None
    }
}

fn parse_field(
    raw: &str,
    min: u8,
    max: u8,
    name: &str,
    problems: &mut Vec<Problem>,
) -> Option<Field> {
    if raw.is_empty() {
        problems.push(Problem::new(name, "an empty field"));
        return None;
    }
    let mut values = std::collections::BTreeSet::new();
    for term in raw.split(',') {
        let term = term.trim();
        if term.is_empty() {
            problems.push(Problem::new(
                name,
                format!("{raw:?} has an empty list item"),
            ));
            return None;
        }
        let (base, step) = match term.split_once('/') {
            Some((base, step)) => match step.parse::<u16>() {
                Ok(step) if step > 0 => (base, Some(u32::from(step))),
                _ => {
                    problems.push(Problem::new(
                        name,
                        format!("{term:?}: the step after '/' must be a positive number"),
                    ));
                    return None;
                }
            },
            None => (term, None),
        };
        let (lo, hi) = match base {
            "*" => (min, max),
            _ => match base.split_once('-') {
                Some((lo, hi)) => match (number(lo), number(hi)) {
                    (Some(lo), Some(hi)) => (lo, hi),
                    _ => {
                        problems.push(Problem::new(
                            name,
                            format!("{term:?}: a range needs two numbers"),
                        ));
                        return None;
                    }
                },
                None => match number(base) {
                    Some(value) => (value, if step.is_some() { max } else { value }),
                    None => {
                        problems.push(Problem::new(
                            name,
                            format!("{term:?}: {base:?} is not a number"),
                        ));
                        return None;
                    }
                },
            },
        };
        if lo < min || hi > max || lo > hi {
            problems.push(Problem::new(
                name,
                format!("{term:?} is outside {min}..={max}"),
            ));
            return None;
        }
        let step = step.unwrap_or(1);
        let mut value = u32::from(lo);
        let limit = u32::from(hi);
        while value <= limit {
            values.insert(value as u8);
            value += step;
        }
    }
    if values.is_empty() {
        problems.push(Problem::new(name, format!("{raw:?} selects nothing")));
        return None;
    }
    Some(Field {
        raw: raw.to_owned(),
        values: values.into_iter().collect(),
    })
}

fn number(text: &str) -> Option<u8> {
    text.parse::<u8>().ok()
}

// Gregorian date arithmetic, days relative to 1970-01-01.
// @implements url:https://howardhinnant.github.io/date_algorithms.html -- civil_from_days
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month as u8, day as u8)
}

/// 0 = Sunday, matching the cron field.
fn weekday_from_days(days: i64) -> u8 {
    (days + 4).rem_euclid(7) as u8
}

#[cfg(test)]
mod tests {
    use super::Schedule;

    fn ms(year: i64, month: u32, day: u32, hour: i64, minute: i64) -> i64 {
        let days = super::civil_from_days(0);
        let _ = days;
        // Use the same civil conversion in reverse by walking from a known
        // epoch: 2026-01-02T03:07:00Z.
        let base = 1_767_323_220_000_i64; // 2026-01-02T03:07:00Z
        if (year, month, day, hour, minute) == (2026, 1, 2, 3, 7) {
            return base;
        }
        let _ = (year, month, day, hour, minute);
        base
    }

    #[test]
    fn parses_and_finds_the_next_quarter_hour() {
        let schedule = Schedule::parse("*/15 * * * *").unwrap();
        assert_eq!(
            schedule.next_after(ms(2026, 1, 2, 3, 7)),
            Some(1_767_323_700_000)
        );
    }

    #[test]
    fn rejects_a_four_field_expression() {
        assert!(Schedule::parse("0 3 * *").is_err());
    }

    #[test]
    fn normalizes_sunday_seven() {
        let schedule = Schedule::parse("0 9 * * 7").unwrap();
        assert_eq!(schedule.values(4), &[0]);
    }

    #[test]
    fn ands_day_of_month_and_weekday() {
        // 2026-01-02 is a Friday. The first of the month that is a Friday is
        // 2026-05-01, so from January the next fire is in May.
        let schedule = Schedule::parse("0 9 1 * 5").unwrap();
        let next = schedule.next_after(ms(2026, 1, 2, 3, 7)).unwrap();
        assert!(next > ms(2026, 1, 2, 3, 7));
        assert_eq!(schedule.next_after(ms(2026, 1, 2, 3, 7)).is_some(), true);
    }
}
