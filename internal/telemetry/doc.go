// Package telemetry exposes LogShield's operational state: Prometheus metrics,
// liveness and readiness endpoints. It is stdlib-only on purpose (ADR 0004): the
// exposition format is small and stable, and a security proxy should not pull in
// a dependency tree for it.
//
// Every metric label comes from a closed set (actions, decisions, rule IDs,
// rejection reasons, budgets), never from request data, so a client cannot
// inflate the number of series.
package telemetry
