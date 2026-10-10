package proxy

import (
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Action says what the proxy did with a request.
type Action string

const (
	// ActionForwarded means the request was sent to the upstream.
	ActionForwarded Action = "forwarded"
	// ActionBlocked means the verdict (or a fail-closed error) stopped the request.
	ActionBlocked Action = "blocked"
	// ActionRejected means the request could not be forwarded faithfully
	// (unsupported or malformed framing, oversize body) and never reached the engine's verdict.
	ActionRejected Action = "rejected"
	// ActionError means forwarding failed (upstream unreachable, or the
	// pre-wire guard stopped the request).
	ActionError Action = "error"
)

// Event is the outcome of one request, delivered to an Observer.
type Event struct {
	ID     string
	Mode   Mode
	Action Action
	// Status is the HTTP status sent to the client.
	Status int
	// Decision is the engine's verdict; DecisionClean if the engine did not run.
	Decision engine.Decision
	// WouldBlock is true when monitor mode forwarded a request that block mode
	// would have stopped.
	WouldBlock bool
	Rules      []engine.RuleID
	Exhausted  engine.Budget
	// Reason is a short stable code for rejections and errors.
	Reason string
	// Remote is the client address; set for requests refused by the HTTP server
	// before the proxy saw them (Reason "protocol-error").
	Remote string
	// FailedOpen is true when an inspection error was overridden by FailOpen.
	FailedOpen      bool
	BodyBytes       int
	BodyTruncated   bool // only the first MaxBodyBytes were inspected (monitor mode)
	BodySkipped     bool // body type is on the skip list
	InspectDuration time.Duration
	Duration        time.Duration
}

// ReasonInspectionError is the Event.Reason when the engine itself failed. It is
// reported even when the request was forwarded (monitor mode, or fail-open).
const ReasonInspectionError = reasonInspection

// Observer receives one Event per request. Implementations must be safe for
// concurrent use and must not block.
type Observer interface {
	Observe(Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Event)

// Observe calls f.
func (f ObserverFunc) Observe(e Event) { f(e) }
