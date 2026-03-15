
package events

import (
	"context"
	"sync"
	"time"
)


type Event struct {

	Type string


	Source string


	Timestamp time.Time


	Data interface{}


	Metadata map[string]interface{}
}


type EventHandler func(event Event)


type EventBus interface {

	Publish(event Event) error


	PublishAsync(event Event)


	Subscribe(eventType string) <-chan Event


	SubscribeFunc(eventType string, handler EventHandler) (unsubscribe func())


	SubscribeAll() <-chan Event


	Unsubscribe(eventType string, ch <-chan Event)


	Close()
}


type subscription struct {
	ch      chan Event
	handler EventHandler
}


type eventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]subscription
	allSubs     []subscription
	bufferSize  int
	closed      bool
	wg          sync.WaitGroup
}


func NewEventBus(bufferSize int) EventBus {
	if bufferSize < 1 {
		bufferSize = 100
	}
	return &eventBus{
		subscribers: make(map[string][]subscription),
		allSubs:     make([]subscription, 0),
		bufferSize:  bufferSize,
	}
}


func (eb *eventBus) Publish(event Event) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return ErrEventBusClosed
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}


	if subs, ok := eb.subscribers[event.Type]; ok {
		for _, sub := range subs {
			if sub.handler != nil {
				sub.handler(event)
			} else {
				select {
				case sub.ch <- event:
				default:
				}
			}
		}
	}

	for _, sub := range eb.allSubs {
		if sub.handler != nil {
			sub.handler(event)
		} else {
			select {
			case sub.ch <- event:
			default:
			}
		}
	}

	return nil
}


func (eb *eventBus) PublishAsync(event Event) {
	eb.wg.Add(1)
	go func() {
		defer eb.wg.Done()
		_ = eb.Publish(event)
	}()
}


func (eb *eventBus) Subscribe(eventType string) <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)
	return ch
}


func (eb *eventBus) SubscribeFunc(eventType string, handler EventHandler) func() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	sub := subscription{handler: handler}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], sub)


	return func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		subs := eb.subscribers[eventType]
		for i, s := range subs {
			if s.handler != nil && &s.handler == &handler {
				eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
}


func (eb *eventBus) SubscribeAll() <-chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan Event, eb.bufferSize)
	sub := subscription{ch: ch}
	eb.allSubs = append(eb.allSubs, sub)
	return ch
}


func (eb *eventBus) Unsubscribe(eventType string, ch <-chan Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subs := eb.subscribers[eventType]
	for i, sub := range subs {
		if sub.ch == ch {
			close(sub.ch)
			eb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
			return
		}
	}


	for i, sub := range eb.allSubs {
		if sub.ch == ch {
			close(sub.ch)
			eb.allSubs = append(eb.allSubs[:i], eb.allSubs[i+1:]...)
			return
		}
	}
}


func (eb *eventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return
	}
	eb.closed = true


	eb.wg.Wait()


	for _, subs := range eb.subscribers {
		for _, sub := range subs {
			if sub.ch != nil {
				close(sub.ch)
			}
		}
	}
	for _, sub := range eb.allSubs {
		if sub.ch != nil {
			close(sub.ch)
		}
	}
}


const (
	EventTypeSessionCreated = "session.created"
	EventTypeSessionUpdated = "session.updated"
	EventTypeSessionRemoved = "session.removed"
	EventTypeSessionExpired = "session.expired"
	EventTypeSessionRekeyed = "session.rekeyed"

	EventTypePacketReceived = "packet.received"
	EventTypePacketSent     = "packet.sent"
	EventTypePacketDropped  = "packet.dropped"

	EventTypeHandshakeStarted   = "handshake.started"
	EventTypeHandshakeCompleted = "handshake.completed"
	EventTypeHandshakeFailed    = "handshake.failed"

	EventTypeConfigReloaded = "config.reloaded"
	EventTypeModuleStarted  = "module.started"
	EventTypeModuleStopped  = "module.stopped"
	EventTypeModuleError    = "module.error"

	EventTypeHealthChanged = "health.changed"
)


var (
	ErrEventBusClosed = &EventBusError{Message: "event bus is closed"}
)
type EventBusError struct {
	Message string
}

func (e *EventBusError) Error() string {
	return e.Message
}


func NewEvent(eventType, source string, data interface{}) Event {
	return Event{
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  make(map[string]interface{}),
	}
}


func (e Event) WithMetadata(key string, value interface{}) Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}
type TopicMatcher struct {
	pattern string
}


func NewTopicMatcher(pattern string) *TopicMatcher {
	return &TopicMatcher{pattern: pattern}
}


func (tm *TopicMatcher) Matches(eventType string) bool {
	if tm.pattern == "*" {
		return true
	}
	if tm.pattern == eventType {
		return true
	}

	if len(tm.pattern) > 0 && tm.pattern[len(tm.pattern)-1] == '*' {
		prefix := tm.pattern[:len(tm.pattern)-1]
		return len(eventType) >= len(prefix) && eventType[:len(prefix)] == prefix
	}
	return false
}
type EventAggregator struct {
	mu       sync.Mutex
	events   []Event
	window   time.Duration
	callback func(events []Event)
	timer    *time.Timer
}


func NewEventAggregator(window time.Duration, callback func(events []Event)) *EventAggregator {
	return &EventAggregator{
		events:   make([]Event, 0),
		window:   window,
		callback: callback,
	}
}


func (ea *EventAggregator) Add(event Event) {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	ea.events = append(ea.events, event)


	if ea.timer == nil {
		ea.timer = time.AfterFunc(ea.window, ea.flush)
	}
}


func (ea *EventAggregator) flush() {
	ea.mu.Lock()
	events := ea.events
	ea.events = make([]Event, 0)
	ea.timer = nil
	ea.mu.Unlock()

	if len(events) > 0 && ea.callback != nil {
		ea.callback(events)
	}
}


func (ea *EventAggregator) Flush() {
	ea.mu.Lock()
	if ea.timer != nil {
		ea.timer.Stop()
	}
	ea.mu.Unlock()
	ea.flush()
}


type EventFilter struct {
	types   map[string]bool
	sources map[string]bool
}


func NewEventFilter() *EventFilter {
	return &EventFilter{
		types:   make(map[string]bool),
		sources: make(map[string]bool),
	}
}


func (ef *EventFilter) AllowType(eventType string) *EventFilter {
	ef.types[eventType] = true
	return ef
}


func (ef *EventFilter) AllowSource(source string) *EventFilter {
	ef.sources[source] = true
	return ef
}


func (ef *EventFilter) Matches(event Event) bool {
	if len(ef.types) > 0 && !ef.types[event.Type] {
		return false
	}
	if len(ef.sources) > 0 && !ef.sources[event.Source] {
		return false
	}
	return true
}


type FilteredSubscriber struct {
	input  <-chan Event
	output chan Event
	filter *EventFilter
	ctx    context.Context
	cancel context.CancelFunc
}


func NewFilteredSubscriber(input <-chan Event, filter *EventFilter, bufferSize int) *FilteredSubscriber {
	ctx, cancel := context.WithCancel(context.Background())
	fs := &FilteredSubscriber{
		input:  input,
		output: make(chan Event, bufferSize),
		filter: filter,
		ctx:    ctx,
		cancel: cancel,
	}
	go fs.run()
	return fs
}


func (fs *FilteredSubscriber) Channel() <-chan Event {
	return fs.output
}
func (fs *FilteredSubscriber) Close() {
	fs.cancel()
}

func (fs *FilteredSubscriber) run() {
	defer close(fs.output)
	for {
		select {
		case <-fs.ctx.Done():
			return
		case event, ok := <-fs.input:
			if !ok {
				return
			}
			if fs.filter.Matches(event) {
				select {
				case fs.output <- event:
				case <-fs.ctx.Done():
					return
				}
			}
		}
	}
}
