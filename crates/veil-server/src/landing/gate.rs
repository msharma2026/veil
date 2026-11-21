//! agent-ci fork: gated branches, the verifier's side of the landing queue
//! (agent-ci design §6.2 A1, A4).
//!
//! `[branches.main] gated = true` in `.veilrules` (which implies
//! `protected`) changes one thing for the branch's landing service: it
//! lands only the queue rows a verifier approved, in the verifier's order,
//! and only while the branch's tip is the tip they were approved on. Every
//! push and `POST …/land` onto the branch is still judged and queued as
//! before (the same checks, the same stack encoding); it then waits.
//!
//! The verifier (a project admin: it reads the queue's real ids) uses
//! three routes:
//!
//! * `GET /v1/projects/{p}/gate/{branch}?after=SEQ&limit=N`: the queue's
//!   rows with `seq > SEQ` in `seq` order, any state (finished rows stay an
//!   hour, as every landing's do), and the branch's tip. This is the durable
//!   submission feed (A4): a coordinator that restarts reads it again from
//!   its last cursor. `seq` is assigned at insert, so a row of a slow
//!   transaction may appear below the cursor: clients re-read a small
//!   overlap and deduplicate by `seq`.
//! * `POST …/gate/{branch}/approve` `{"expected_tip": HEX, "seqs": [..]}`:
//!   the rows land, in that order, on `expected_tip`. A row whose approval
//!   tip is not the tip its batch builds on waits (the compare-and-swap of
//!   `CommitBatch`); approving it again with a new tip replaces it.
//! * `POST …/gate/{branch}/reject` `{"seq": N, "reason": "..."}`: the row
//!   finishes `rejected` with the reason as its message, which its
//!   submitter's `vl land` / `GET …/land/{ticket}` reports.

use std::{collections::BTreeSet, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use veil_core::ObjectId;

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm, Hub, HubState,
};

/// The gated branches of `project`: the rules of its default branch's tip.
pub async fn is_gated(hub: &Arc<Hub>, project: i64) -> Result<BTreeSet<String>> {
    let tip: Option<String> = sqlx::query_scalar(
        "SELECT b.target FROM projects p JOIN branches b ON b.project_id = p.id AND b.name = p.default_branch \
         WHERE p.id = $1 AND b.hidden_for_embargo IS NULL",
    )
    .bind(project)
    .fetch_optional(&hub.db)
    .await?;
    let Some(tip) = tip else { return Ok(BTreeSet::new()) };
    let tip = ObjectId::from_hex(&tip).map_err(|e| Error::Other(e.into()))?;
    crate::sync::blocking(hub, project, move |src| Ok(super::rules(src, Some(tip))?.gated)).await
}

async fn open_verifier(hub: &HubState, p: &str, caller: &Caller, branch: &str) -> Result<perm::Project> {
    let (project, viewer) = perm::open(hub, p, caller).await?;
    if !viewer.admin {
        return Err(Error::forbidden("only an admin of the project verifies a gated branch"));
    }
    if !is_gated(hub, project.id).await?.contains(branch) {
        return Err(Error::bad_request(format!("'{branch}' is not gated (`[branches.{branch}] gated = true` in .veilrules)")));
    }
    Ok(project)
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    after: i64,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct GateEntry {
    seq: i64,
    ticket: String,
    person: String,
    agent_session: Option<String>,
    /// `[snapshot, base]` pairs, oldest first (real ids).
    stack: Vec<[ObjectId; 2]>,
    state: String,
    gate_ok: bool,
    gate_tip: Option<String>,
    priority: i32,
    created_at: i64,
    result: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct GateList {
    tip: Option<String>,
    entries: Vec<GateEntry>,
    /// The cursor for the next read: the last `seq` returned (or `after`).
    next: i64,
}

type ListRow = (i64, String, String, Option<String>, String, String, bool, Option<String>, i32, i64, Option<String>);

pub async fn list_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, branch)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Json<GateList>> {
    let project = open_verifier(&hub, &p, &caller, &branch).await?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows: Vec<ListRow> = sqlx::query_as(
        "SELECT seq, ticket, person_name, agent_session, stack, state, gate_ok, gate_tip, priority, created_at, result \
         FROM landing_queue WHERE project_id = $1 AND branch = $2 AND seq > $3 ORDER BY seq LIMIT $4",
    )
    .bind(project.id)
    .bind(&branch)
    .bind(q.after)
    .bind(limit)
    .fetch_all(&hub.db)
    .await?;
    let tip: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
        .bind(project.id)
        .bind(&branch)
        .fetch_optional(&hub.db)
        .await?;
    let mut next = q.after;
    let mut entries = Vec::with_capacity(rows.len());
    for (seq, ticket, person, agent_session, stack, state, gate_ok, gate_tip, priority, created_at, result) in rows {
        next = next.max(seq);
        let stack = super::decode_stack(&stack)?.into_iter().map(|e| [e.id, e.base]).collect();
        entries.push(GateEntry {
            seq,
            ticket,
            person,
            agent_session,
            stack,
            state,
            gate_ok,
            gate_tip,
            priority,
            created_at,
            result: result.and_then(|r| serde_json::from_str(&r).ok()),
        });
    }
    Ok(Json(GateList { tip, entries, next }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approve {
    expected_tip: ObjectId,
    seqs: Vec<i64>,
}

#[derive(Serialize)]
pub struct Approved {
    /// The rows approved (queued ones), in order.
    approved: Vec<i64>,
    /// The rows that were not queued any more (landed, rejected, gone).
    not_queued: Vec<i64>,
}

pub async fn approve_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, branch)): Path<(String, String)>,
    Json(req): Json<Approve>,
) -> Result<Json<Approved>> {
    let project = open_verifier(&hub, &p, &caller, &branch).await?;
    if req.seqs.is_empty() || req.seqs.len() > 1000 {
        return Err(Error::bad_request("approve 1 to 1000 rows"));
    }
    // The verifier's order: after every earlier approval (microseconds on
    // the database's clock, times 1000, plus the position).
    let mut tx = hub.db.begin().await?;
    let base: i64 = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::BIGINT * 1000")
        .fetch_one(&mut *tx)
        .await?;
    let tip = req.expected_tip.to_string();
    let (mut approved, mut not_queued) = (Vec::new(), Vec::new());
    for (i, seq) in req.seqs.iter().enumerate() {
        let n = sqlx::query(
            "UPDATE landing_queue SET gate_ok = true, gate_tip = $4, gate_order = $5 \
             WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'queued'",
        )
        .bind(project.id)
        .bind(&branch)
        .bind(seq)
        .bind(&tip)
        .bind(base + i as i64)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 1 {
            approved.push(*seq);
        } else {
            not_queued.push(*seq);
        }
    }
    tx.commit().await?;
    super::ensure(&hub, project.id, &branch);
    Ok(Json(Approved { approved, not_queued }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reject {
    seq: i64,
    reason: String,
}

#[derive(Serialize)]
pub struct Rejected {
    rejected: bool,
}

pub async fn reject_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, branch)): Path<(String, String)>,
    Json(req): Json<Reject>,
) -> Result<Json<Rejected>> {
    let project = open_verifier(&hub, &p, &caller, &branch).await?;
    let reason: String = req.reason.chars().take(2000).collect();
    let ticket: Option<String> = sqlx::query_scalar(
        "SELECT ticket FROM landing_queue WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'queued'",
    )
    .bind(project.id)
    .bind(&branch)
    .bind(req.seq)
    .fetch_optional(&hub.db)
    .await?;
    let Some(ticket) = ticket else { return Ok(Json(Rejected { rejected: false })) };
    let mut r = super::queued(&ticket);
    r.state = veil_core::hub::land::LandState::Rejected;
    r.message = Some(format!("rejected by the verifier: {reason}"));
    let result = serde_json::to_string(&r).map_err(|e| Error::Other(e.into()))?;
    let n = sqlx::query(
        "UPDATE landing_queue SET state = 'rejected', result = $4, gate_ok = false, \
         done_at = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::BIGINT \
         WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'queued'",
    )
    .bind(project.id)
    .bind(&branch)
    .bind(req.seq)
    .bind(&result)
    .execute(&hub.db)
    .await?
    .rows_affected();
    super::ensure(&hub, project.id, &branch);
    Ok(Json(Rejected { rejected: n == 1 }))
}
