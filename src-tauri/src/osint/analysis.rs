// SPDX-License-Identifier: Apache-2.0
//! Graph analysis over an investigation's relationships (or a graph's membership). Results are
//! structural facts with the relationships that support them; they never label an entity as
//! malicious or related in ownership — high connectivity only means "many links".

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::Serialize;

use super::store::{EntityBrief, RelationshipBrief};

pub struct Graph<'a> {
    entities: HashMap<i64, &'a EntityBrief>,
    adj: HashMap<i64, Vec<(i64, &'a RelationshipBrief)>>,
    rels: Vec<&'a RelationshipBrief>,
}

impl<'a> Graph<'a> {
    /// `include_inferred`: whether unreviewed inferred links count. Rejected links never count.
    pub fn new(entities: &'a [EntityBrief], rels: &'a [RelationshipBrief], include_inferred: bool) -> Self {
        let entities: HashMap<i64, &EntityBrief> = entities.iter().map(|e| (e.id, e)).collect();
        let mut adj: HashMap<i64, Vec<(i64, &RelationshipBrief)>> = HashMap::new();
        let mut kept = vec![];
        for r in rels {
            if r.verification == "rejected" || (!include_inferred && r.verification == "inferred") {
                continue;
            }
            if !entities.contains_key(&r.source) || !entities.contains_key(&r.target) {
                continue;
            }
            adj.entry(r.source).or_default().push((r.target, r));
            adj.entry(r.target).or_default().push((r.source, r));
            kept.push(r);
        }
        Graph { entities, adj, rels: kept }
    }

    fn degree(&self, id: i64) -> usize {
        self.adj.get(&id).map_or(0, |v| v.len())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Path {
    pub entities: Vec<i64>,
    pub relationships: Vec<i64>,
    pub explanation: String,
}

/// Shortest path (fewest relationships, direction ignored) between two entities.
pub fn shortest_path(g: &Graph, from: i64, to: i64, max_depth: usize) -> Option<Path> {
    if !g.entities.contains_key(&from) || !g.entities.contains_key(&to) {
        return None;
    }
    if from == to {
        return Some(Path { entities: vec![from], relationships: vec![], explanation: "Same entity.".into() });
    }
    let mut prev: HashMap<i64, (i64, i64)> = HashMap::new();
    let mut seen: HashSet<i64> = HashSet::from([from]);
    let mut q = VecDeque::from([(from, 0usize)]);
    while let Some((n, d)) = q.pop_front() {
        if d >= max_depth {
            continue;
        }
        // deterministic order: by neighbour id, then relationship id
        let mut next: Vec<&(i64, &RelationshipBrief)> = g.adj.get(&n).map(|v| v.iter().collect()).unwrap_or_default();
        next.sort_by_key(|(m, r)| (*m, r.id));
        for (m, r) in next {
            if seen.insert(*m) {
                prev.insert(*m, (n, r.id));
                if *m == to {
                    let mut entities = vec![to];
                    let mut relationships = vec![];
                    let mut cur = to;
                    while let Some((p, rid)) = prev.get(&cur) {
                        relationships.push(*rid);
                        entities.push(*p);
                        cur = *p;
                    }
                    entities.reverse();
                    relationships.reverse();
                    let hops = relationships.len();
                    let explanation = format!(
                        "Connected through {hops} relationship{} ({}). A path shows that the records link up; it does not by itself establish ownership or intent.",
                        if hops == 1 { "" } else { "s" },
                        relationships.iter().filter_map(|id| g.rels.iter().find(|r| r.id == *id)).map(|r| r.rel_type.as_str()).collect::<Vec<_>>().join(" → ")
                    );
                    return Some(Path { entities, relationships, explanation });
                }
                q.push_back((*m, d + 1));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub entities: Vec<i64>,
    pub relationships: usize,
}

pub fn components(g: &Graph) -> Vec<Component> {
    let mut seen = HashSet::new();
    let mut ids: Vec<i64> = g.entities.keys().copied().collect();
    ids.sort();
    let mut out = vec![];
    for start in ids {
        if !seen.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut q = VecDeque::from([start]);
        while let Some(n) = q.pop_front() {
            for (m, _) in g.adj.get(&n).into_iter().flatten() {
                if seen.insert(*m) {
                    comp.push(*m);
                    q.push_back(*m);
                }
            }
        }
        comp.sort();
        let set: HashSet<i64> = comp.iter().copied().collect();
        let relationships = g.rels.iter().filter(|r| set.contains(&r.source)).count();
        out.push(Component { entities: comp, relationships });
    }
    out.sort_by(|a, b| b.entities.len().cmp(&a.entities.len()).then(a.entities[0].cmp(&b.entities[0])));
    out
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Centrality {
    pub entity: i64,
    pub degree: usize,
    /// degree / (n - 1)
    pub normalized: f64,
    pub by_type: BTreeMap<String, usize>,
}

pub fn degree_centrality(g: &Graph, top: usize) -> Vec<Centrality> {
    let n = g.entities.len().max(2) as f64;
    let mut v: Vec<Centrality> = g
        .entities
        .keys()
        .map(|id| {
            let mut by_type = BTreeMap::new();
            for (_, r) in g.adj.get(id).into_iter().flatten() {
                *by_type.entry(r.rel_type.clone()).or_insert(0) += 1;
            }
            let degree = g.degree(*id);
            Centrality { entity: *id, degree, normalized: degree as f64 / (n - 1.0), by_type }
        })
        .filter(|c| c.degree > 0)
        .collect();
    v.sort_by(|a, b| b.degree.cmp(&a.degree).then(a.entity.cmp(&b.entity)));
    v.truncate(top);
    v
}

pub fn isolated(g: &Graph) -> Vec<i64> {
    let mut v: Vec<i64> = g.entities.keys().copied().filter(|id| g.degree(*id) == 0).collect();
    v.sort();
    v
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedInfrastructure {
    /// the shared element (address, network, AS, provider, name server, certificate)
    pub infrastructure: i64,
    pub via: String,
    /// entities (usually domains) using it
    pub members: Vec<i64>,
    pub relationships: Vec<i64>,
    pub note: String,
}

const INFRA_RELS: &[&str] = &["RESOLVES_TO", "USES_NAMESERVER", "USES_MAIL_SERVER", "USES_CERTIFICATE", "HOSTED_ON", "PART_OF", "ROUTES_THROUGH"];

/// Infrastructure elements used by two or more entities, with the relationships showing it.
pub fn shared_infrastructure(g: &Graph) -> Vec<SharedInfrastructure> {
    let mut by_target: BTreeMap<(i64, String), Vec<(i64, i64)>> = BTreeMap::new();
    for r in &g.rels {
        if INFRA_RELS.contains(&r.rel_type.as_str()) {
            by_target.entry((r.target, r.rel_type.clone())).or_default().push((r.source, r.id));
        }
    }
    let mut out: Vec<SharedInfrastructure> = by_target
        .into_iter()
        .filter(|(_, v)| v.len() >= 2)
        .map(|((infra, via), v)| {
            let n = v.len();
            SharedInfrastructure {
                infrastructure: infra,
                via,
                members: v.iter().map(|(s, _)| *s).collect(),
                relationships: v.iter().map(|(_, r)| *r).collect(),
                note: if n > super::ingest::SHARED_INFRA_FANOUT_LIMIT {
                    format!("Shared by {n} entities — typical of CDNs, large hosters or public services; on its own it says little.")
                } else {
                    format!("Shared by {n} entities. Shared infrastructure can point to a common operator, but hosting and DNS providers serve many unrelated customers.")
                },
            }
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.members.len()));
    out
}

/// Entities within `depth` hops.
pub fn neighborhood(g: &Graph, start: i64, depth: usize) -> Vec<i64> {
    let mut seen = HashSet::from([start]);
    let mut q = VecDeque::from([(start, 0)]);
    while let Some((n, d)) = q.pop_front() {
        if d >= depth {
            continue;
        }
        for (m, _) in g.adj.get(&n).into_iter().flatten() {
            if seen.insert(*m) {
                q.push_back((*m, d + 1));
            }
        }
    }
    let mut v: Vec<i64> = seen.into_iter().collect();
    v.sort();
    v
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub entities: usize,
    pub relationships: usize,
    pub components: Vec<Component>,
    pub hubs: Vec<Centrality>,
    pub isolated: Vec<i64>,
    pub shared_infrastructure: Vec<SharedInfrastructure>,
    pub explanation: Vec<String>,
}

pub fn overview(g: &Graph) -> Overview {
    let components = components(g);
    let hubs = degree_centrality(g, 15);
    let isolated = isolated(g);
    let shared = shared_infrastructure(g);
    let explanation = vec![
        "Connected components are groups of entities linked to each other; separate components share no recorded relationship.".into(),
        "Degree counts an entity's relationships. A highly connected entity is a hub of the collected data (often shared infrastructure), not evidence of malicious activity.".into(),
        "Isolated entities have no recorded relationships yet: they are candidates for further collection.".into(),
        "Shared infrastructure lists addresses, networks, name servers or certificates used by several entities, with the relationships that show it. It can indicate a common operator but does not prove it.".into(),
    ];
    Overview { entities: g.entities.len(), relationships: g.rels.len(), components: components.into_iter().take(50).collect(), hubs, isolated, shared_infrastructure: shared.into_iter().take(50).collect(), explanation }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: i64, t: &str) -> EntityBrief {
        EntityBrief { id, entity_type: t.into(), value: format!("v{id}"), display_name: format!("v{id}"), verification: "observed".into(), confidence: "high".into(), flagged: false }
    }
    fn r(id: i64, s: i64, t: i64, ty: &str, ver: &str) -> RelationshipBrief {
        RelationshipBrief { id, source: s, target: t, rel_type: ty.into(), directed: true, origin: "observed".into(), verification: ver.into(), confidence: "high".into() }
    }

    #[test]
    fn paths_components_hubs_and_shared_infrastructure() {
        let ents = vec![e(1, "domain"), e(2, "ip"), e(3, "domain"), e(4, "asn"), e(5, "domain"), e(6, "email")];
        let rels = vec![
            r(10, 1, 2, "RESOLVES_TO", "observed"),
            r(11, 3, 2, "RESOLVES_TO", "observed"),
            r(12, 2, 4, "ROUTES_THROUGH", "observed"),
            r(13, 5, 4, "ASSOCIATED_WITH", "inferred"),
            r(14, 1, 3, "SHARES_INFRASTRUCTURE", "rejected"),
        ];
        let g = Graph::new(&ents, &rels, false);
        let p = shortest_path(&g, 1, 4, 6).unwrap();
        assert_eq!((p.entities, p.relationships), (vec![1, 2, 4], vec![10, 12]));
        assert!(p.explanation.contains("RESOLVES_TO → ROUTES_THROUGH"));
        assert!(shortest_path(&g, 1, 5, 6).is_none(), "inferred links are excluded unless requested");
        assert!(shortest_path(&Graph::new(&ents, &rels, true), 1, 5, 6).is_some());
        assert!(shortest_path(&g, 1, 4, 1).is_none(), "depth limit");
        let comps = components(&g);
        assert_eq!(comps[0].entities, vec![1, 2, 3, 4]);
        assert_eq!(comps.len(), 3, "5 and 6 are on their own");
        assert_eq!(isolated(&g), vec![5, 6]);
        let hubs = degree_centrality(&g, 3);
        assert_eq!((hubs[0].entity, hubs[0].degree), (2, 3));
        let shared = shared_infrastructure(&g);
        assert_eq!(shared.len(), 1);
        assert_eq!((shared[0].infrastructure, shared[0].members.len(), shared[0].relationships.clone()), (2, 2, vec![10, 11]));
        assert_eq!(neighborhood(&g, 1, 1), vec![1, 2]);
        assert_eq!(neighborhood(&g, 1, 2), vec![1, 2, 3, 4]);
        let o = overview(&g);
        assert_eq!((o.entities, o.relationships), (6, 3));
        assert!(o.explanation.iter().any(|x| x.contains("not evidence of malicious activity")));
    }
}
