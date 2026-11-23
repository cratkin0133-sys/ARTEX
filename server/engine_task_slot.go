package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// taskSlot holds all per-task Engine state that used to live in separate sync.Maps.
// StopTask drops the whole slot so teardown cannot miss a field (e.g. goalFP).
type taskSlot struct {
	mu sync.Mutex

	started      bool
	paused       bool
	deleting     bool
	settling     bool
	stamped      bool
	coordStarted bool

	plannerRound int

	lastAct int64

	deadline    int64
	deadlineSet bool

	goalFP  string
	goalSet bool

	inflight *int64
	llmCalls *int64
	dropCnt  *int64
	budgets  *agent.BudgetLedger
}

func (e *Engine) loadSlot(taskID string) (*taskSlot, bool) {
	if e == nil || taskID == "" {
		return nil, false
	}
	v, ok := e.slots.Load(taskID)
	if !ok {
		return nil, false
	}
	return v.(*taskSlot), true
}

func (e *Engine) slot(taskID string) *taskSlot {
	if e == nil || taskID == "" {
		return &taskSlot{}
	}
	v, _ := e.slots.LoadOrStore(taskID, &taskSlot{})
	return v.(*taskSlot)
}

func (e *Engine) dropTaskSlot(taskID string) {
	if e == nil || taskID == "" {
		return
	}
	e.slots.Delete(taskID)
}

func (s *taskSlot) int64Counter(dst **int64) *int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *dst == nil {
		*dst = new(int64)
	}
	return *dst
}

func (s *taskSlot) bumpDrop() int64 {
	return atomic.AddInt64(s.int64Counter(&s.dropCnt), 1)
}

func (s *taskSlot) nextPlannerRound() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plannerRound++
	return s.plannerRound
}

func (s *taskSlot) setPaused(v bool) {
	s.mu.Lock()
	s.paused = v
	s.mu.Unlock()
}

func (s *taskSlot) isPaused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused
}

func (s *taskSlot) tryMarkDeleting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleting {
		return false
	}
	s.deleting = true
	return true
}

func (s *taskSlot) setDeleting(v bool) {
	s.mu.Lock()
	s.deleting = v
	s.mu.Unlock()
}

func (s *taskSlot) isDeleting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleting
}

func (s *taskSlot) tryMarkStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return true
	}
	s.started = true
	return false
}

func (s *taskSlot) clearStarted() {
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
}

func (s *taskSlot) isStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

func (s *taskSlot) touch() {
	atomic.StoreInt64(&s.lastAct, time.Now().Unix())
}

func (s *taskSlot) lastActivity() int64 {
	return atomic.LoadInt64(&s.lastAct)
}

func (s *taskSlot) beginLLMCall() {
	atomic.AddInt64(s.int64Counter(&s.llmCalls), 1)
}

func (s *taskSlot) endLLMCall() {
	s.mu.Lock()
	ptr := s.llmCalls
	s.mu.Unlock()
	if ptr == nil {
		return
	}
	if atomic.AddInt64(ptr, -1) <= 0 {
		atomic.StoreInt64(ptr, 0)
	}
}

func (s *taskSlot) activeLLMCalls() int64 {
	s.mu.Lock()
	ptr := s.llmCalls
	s.mu.Unlock()
	if ptr == nil {
		return 0
	}
	return atomic.LoadInt64(ptr)
}

func (s *taskSlot) openGoalFP() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goalFP, s.goalSet
}

func (s *taskSlot) storeGoalFP(fp string) {
	s.mu.Lock()
	s.goalFP, s.goalSet = fp, true
	s.mu.Unlock()
}

func (s *taskSlot) isSettling() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settling
}

func (s *taskSlot) tryMarkSettling() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settling {
		return false
	}
	s.settling = true
	return true
}

func (s *taskSlot) clearSettling() {
	s.mu.Lock()
	s.settling = false
	s.mu.Unlock()
}

func (s *taskSlot) inflightPtr() *int64 {
	return s.int64Counter(&s.inflight)
}

func (s *taskSlot) inflightValue() int64 {
	s.mu.Lock()
	ptr := s.inflight
	s.mu.Unlock()
	if ptr == nil {
		return 0
	}
	return atomic.LoadInt64(ptr)
}

func (s *taskSlot) getDeadline() (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline, s.deadlineSet
}

func (s *taskSlot) setDeadline(dl int64) {
	s.mu.Lock()
	s.deadline, s.deadlineSet = dl, true
	s.mu.Unlock()
}

func (s *taskSlot) clearDeadline() {
	s.mu.Lock()
	s.deadline, s.deadlineSet = 0, false
	s.mu.Unlock()
}

func (s *taskSlot) tryMarkStamped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stamped {
		return true
	}
	s.stamped = true
	return false
}

func (s *taskSlot) clearStamped() {
	s.mu.Lock()
	s.stamped = false
	s.mu.Unlock()
}

func (s *taskSlot) tryMarkCoordStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coordStarted {
		return true
	}
	s.coordStarted = true
	return false
}

func (s *taskSlot) clearCoordStarted() {
	s.mu.Lock()
	s.coordStarted = false
	s.mu.Unlock()
}

func (s *taskSlot) budgetLedger() *agent.BudgetLedger {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.budgets
}

func (s *taskSlot) setBudgetLedger(l *agent.BudgetLedger) (*agent.BudgetLedger, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.budgets != nil {
		return s.budgets, true
	}
	s.budgets = l
	return l, false
}

func (s *taskSlot) clearBudget() {
	s.mu.Lock()
	s.budgets = nil
	s.mu.Unlock()
}

// resetTimeoutFields clears per-run timeout state without removing the slot.
func (s *taskSlot) resetTimeoutFields() {
	s.clearSettling()
	s.clearDeadline()
	s.clearStamped()
	s.clearCoordStarted()
	s.clearBudget()
}

// The helpers below prime state from tests in this package only.

func (s *taskSlot) setStarted(v bool) {
	s.mu.Lock()
	s.started = v
	s.mu.Unlock()
}

func (s *taskSlot) setSettling(v bool) {
	s.mu.Lock()
	s.settling = v
	s.mu.Unlock()
}

func (s *taskSlot) setStamped(v bool) {
	s.mu.Lock()
	s.stamped = v
	s.mu.Unlock()
}

func (s *taskSlot) isStamped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stamped
}

func (s *taskSlot) hasCoordStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coordStarted
}

func (s *taskSlot) setCoordStarted(v bool) {
	s.mu.Lock()
	s.coordStarted = v
	s.mu.Unlock()
}

func (s *taskSlot) setPlannerRound(n int) {
	s.mu.Lock()
	s.plannerRound = n
	s.mu.Unlock()
}

func (s *taskSlot) hasPlannerRound() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plannerRound != 0
}

func (s *taskSlot) setLastActUnix(v int64) {
	atomic.StoreInt64(&s.lastAct, v)
}