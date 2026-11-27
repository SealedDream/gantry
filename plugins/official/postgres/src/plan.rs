//! EXPLAIN as a tree (PLUG-08b; spec section 11: "EXPLAIN and EXPLAIN ANALYZE as a tree with
//! cost and time columns").
//!
//! The plugin runs `EXPLAIN (FORMAT JSON[, ANALYZE, BUFFERS]) <sql>` on the query tab's own
//! session, so read only and the timeout apply: with "Allow changes" off, EXPLAIN ANALYZE of a
//! write fails in the read-only transaction instead of changing data. The SQL must be one
//! statement ([`crate::sqllex::single_statement`]).

use crate::json::{self, Json};
use crate::sqllex;

/// The most plan nodes kept (a plan this large is not readable as a tree anyway).
pub const MAX_NODES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PlanNode {
    /// "Seq Scan on public.t", "Hash Join (Inner)", …
    pub label: String,
    pub startup_cost: Option<f64>,
    pub total_cost: Option<f64>,
    pub plan_rows: Option<f64>,
    /// Milliseconds, per loop, as PostgreSQL reports them (ANALYZE only).
    pub actual_total_ms: Option<f64>,
    pub actual_rows: Option<f64>,
    pub loops: Option<f64>,
    /// "Filter: (id > 3)", "Index Cond: …", shown as leaf items under the node.
    pub details: Vec<String>,
    pub children: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    /// Node 0 is the root.
    pub nodes: Vec<PlanNode>,
    pub planning_ms: Option<f64>,
    pub execution_ms: Option<f64>,
    pub analyzed: bool,
}

/// The statement to run, or why not.
pub fn explain_sql(sql: &str, analyze: bool) -> Result<String, String> {
    if !sqllex::single_statement(sql) {
        return Err("Explain needs exactly one statement. Select one and try again.".into());
    }
    let body = sql.trim().trim_end_matches(|c: char| c == ';' || c.is_whitespace());
    let opts = if analyze { "FORMAT JSON, ANALYZE, BUFFERS" } else { "FORMAT JSON" };
    Ok(format!("EXPLAIN ({opts}) {body}"))
}

/// Keys the tree uses: `plan:<index>`; detail rows are `plan:<index>:<n>`.
pub fn key(i: usize) -> String {
    format!("plan:{i}")
}

/// The node index a tree key names, if it names a node (not a detail row).
pub fn parse_key(key: &str) -> Option<usize> {
    key.strip_prefix("plan:")?.parse().ok()
}

const DETAIL_KEYS: [&str; 12] = [
    "Filter", "Index Cond", "Recheck Cond", "Join Filter", "Hash Cond", "Merge Cond", "Sort Key", "Group Key", "Output", "Rows Removed by Filter", "Heap Fetches", "Sort Method",
];

pub fn parse(text: &str, analyzed: bool) -> Result<Plan, String> {
    let doc = json::parse(text)?;
    let top = doc.as_array().and_then(|a| a.first()).ok_or("The server sent no plan.")?;
    let root = top.get("Plan").ok_or("The server sent no plan.")?;
    let mut plan = Plan {
        planning_ms: top.get("Planning Time").and_then(Json::as_f64),
        execution_ms: top.get("Execution Time").and_then(Json::as_f64),
        analyzed,
        ..Default::default()
    };
    // Iterative, so a deep plan cannot overflow the stack.
    let mut stack: Vec<(&Json, Option<usize>)> = vec![(root, None)];
    while let Some((j, parent)) = stack.pop() {
        if plan.nodes.len() >= MAX_NODES {
            return Err(format!("The plan has more than {MAX_NODES} nodes."));
        }
        let i = plan.nodes.len();
        plan.nodes.push(node(j));
        if let Some(p) = parent {
            plan.nodes[p].children.push(i);
        }
        if let Some(kids) = j.get("Plans").and_then(Json::as_array) {
            for k in kids.iter().rev() {
                stack.push((k, Some(i)));
            }
        }
    }
    // Children were pushed in reverse to pop in order, so they are already in plan order.
    Ok(plan)
}

fn text(j: &Json) -> Option<String> {
    match j {
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(format!("{n}")),
        Json::Bool(b) => Some(b.to_string()),
        Json::Array(a) => Some(a.iter().filter_map(text).collect::<Vec<_>>().join(", ")),
        _ => None,
    }
}

fn node(j: &Json) -> PlanNode {
    let s = |k: &str| j.get(k).and_then(Json::as_str);
    let n = |k: &str| j.get(k).and_then(Json::as_f64);
    let mut label = s("Node Type").unwrap_or("?").to_string();
    if let Some(strategy) = s("Strategy").filter(|v| *v != "Plain") {
        label = format!("{strategy} {label}");
    }
    if let Some(jt) = s("Join Type") {
        label.push_str(&format!(" ({jt})"));
    }
    if let Some(rel) = s("Relation Name") {
        match s("Schema") {
            Some(schema) => label.push_str(&format!(" on {schema}.{rel}")),
            None => label.push_str(&format!(" on {rel}")),
        }
        if let Some(a) = s("Alias").filter(|a| *a != rel) {
            label.push_str(&format!(" {a}"));
        }
    }
    if let Some(ix) = s("Index Name") {
        label.push_str(&format!(" using {ix}"));
    }
    let details = DETAIL_KEYS.iter().filter_map(|k| j.get(k).and_then(text).map(|v| format!("{k}: {v}"))).collect();
    PlanNode {
        label,
        startup_cost: n("Startup Cost"),
        total_cost: n("Total Cost"),
        plan_rows: n("Plan Rows"),
        actual_total_ms: n("Actual Total Time"),
        actual_rows: n("Actual Rows"),
        loops: n("Actual Loops"),
        details,
        children: Vec::new(),
    }
}

/// The status line under the plan.
pub fn summary(p: &Plan) -> String {
    let mut parts = vec![format!("{} nodes", p.nodes.len())];
    if let Some(t) = p.planning_ms {
        parts.push(format!("planning {t:.3} ms"));
    }
    if let Some(t) = p.execution_ms {
        parts.push(format!("execution {t:.3} ms"));
    }
    if !p.analyzed {
        parts.push("estimates only".into());
    }
    parts.join(", ") + "."
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = r#"[{"Plan": {"Node Type": "Hash Join", "Join Type": "Inner", "Startup Cost": 1.5, "Total Cost": 30.25, "Plan Rows": 10,
        "Actual Total Time": 0.42, "Actual Rows": 3, "Actual Loops": 1, "Hash Cond": "(a.id = b.a_id)",
        "Plans": [
          {"Node Type": "Seq Scan", "Relation Name": "a", "Schema": "public", "Alias": "a", "Startup Cost": 0, "Total Cost": 12, "Plan Rows": 200, "Filter": "(id > 3)"},
          {"Node Type": "Hash", "Startup Cost": 1, "Total Cost": 1, "Plan Rows": 1, "Plans": [
             {"Node Type": "Index Scan", "Relation Name": "b", "Schema": "s", "Alias": "x", "Index Name": "b_pkey", "Index Cond": "(id = 1)"}]}
        ]}, "Planning Time": 0.1, "Execution Time": 0.5}]"#;

    #[test]
    fn parses_a_plan_into_a_tree() {
        let p = parse(SAMPLE, true).unwrap();
        assert_eq!(p.nodes.len(), 4);
        assert_eq!(p.nodes[0].label, "Hash Join (Inner)");
        assert_eq!(p.nodes[0].children, vec![1, 2]);
        assert_eq!(p.nodes[1].label, "Seq Scan on public.a");
        assert_eq!(p.nodes[1].details, vec!["Filter: (id > 3)"]);
        assert_eq!(p.nodes[2].children, vec![3]);
        assert_eq!(p.nodes[3].label, "Index Scan on s.b x using b_pkey");
        assert_eq!(p.nodes[0].total_cost, Some(30.25));
        assert_eq!(p.nodes[0].actual_total_ms, Some(0.42));
        assert_eq!(p.nodes[0].details, vec!["Hash Cond: (a.id = b.a_id)"]);
        assert_eq!(summary(&p), "4 nodes, planning 0.100 ms, execution 0.500 ms.");
    }

    #[test]
    fn explain_needs_one_statement() {
        assert_eq!(explain_sql("SELECT 1;  ", false).unwrap(), "EXPLAIN (FORMAT JSON) SELECT 1");
        assert_eq!(explain_sql("SELECT 1", true).unwrap(), "EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) SELECT 1");
        assert!(explain_sql("SELECT 1; DELETE FROM t", true).is_err());
        assert!(explain_sql("", false).is_err());
        assert!(explain_sql("SELECT 'a", false).is_err());
    }

    #[test]
    fn keys_and_hostile_plans() {
        assert_eq!(parse_key(&key(12)), Some(12));
        assert_eq!(parse_key("plan:1:0"), None);
        assert_eq!(parse_key("table:x"), None);
        assert!(parse("[]", false).is_err());
        assert!(parse("[{}]", false).is_err());
        assert!(parse("not json", false).is_err());
        // A very deep plan is refused by the JSON reader, not by a stack overflow.
        let deep = (0..2_000).fold(String::from("{\"Node Type\":\"x\"}"), |acc, _| format!("{{\"Node Type\":\"x\",\"Plans\":[{acc}]}}"));
        assert!(parse(&format!("[{{\"Plan\":{deep}}}]"), false).is_err());
        // Wide plans past the node cap are refused.
        let wide = vec!["{\"Node Type\":\"x\"}"; MAX_NODES + 1].join(",");
        assert!(parse(&format!("[{{\"Plan\":{{\"Node Type\":\"r\",\"Plans\":[{wide}]}}}}]"), false).is_err());
    }
}
