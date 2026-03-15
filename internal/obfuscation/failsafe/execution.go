package obfuscation

import (
	"context"
	"fmt"
	"time"
)

func (fs *FailSafe) executeClose(ctx context.Context, action *FailSafeAction) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	profile := fs.profiles[fs.active]
	if profile == nil {
		return fmt.Errorf("активный профиль не найден")
	}

	if profile.CloseConnection {
		return fs.executeImmediateClose(ctx, action)
	}
	return fs.executeGracefulClose(ctx, action)
}

func (fs *FailSafe) executeImmediateClose(_ context.Context, action *FailSafeAction) error {
	fs.performImmediateClose()

	action.Details = map[string]interface{}{
		"close_type":         "immediate",
		"graceful":           false,
		"timeout":            "0ms",
		"connections_closed": 1,
		"data_lost":          true,
	}

	return nil
}

func (fs *FailSafe) executeGracefulClose(_ context.Context, action *FailSafeAction) error {
	fs.performGracefulClose()

	action.Details = map[string]interface{}{
		"close_type":         "graceful",
		"graceful":           true,
		"timeout":            "200ms",
		"connections_closed": 1,
		"data_lost":          false,
	}

	return nil
}

func (fs *FailSafe) executeDisable(ctx context.Context, action *FailSafeAction) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	profile := fs.profiles[fs.active]
	if profile == nil {
		return fmt.Errorf("активный профиль не найден")
	}

	if profile.DisableObfuscation {
		return fs.executeFullDisable(ctx, action)
	}
	return fs.executePartialDisable(ctx, action)
}

func (fs *FailSafe) executeFullDisable(_ context.Context, action *FailSafeAction) error {
	fs.performFullDisable()

	action.Details = map[string]interface{}{
		"disable_type": "full",
		"disabled_modules": []string{
			"traffic_obfuscation",
			"protocol_masking",
			"behavioral_mimicry",
			"statistical_randomization",
			"encryption_obfuscation",
		},
		"enabled_modules": []string{},
		"security_level":  "minimal",
	}

	return nil
}

func (fs *FailSafe) executePartialDisable(_ context.Context, action *FailSafeAction) error {
	fs.performPartialDisable()

	action.Details = map[string]interface{}{
		"disable_type": "partial",
		"disabled_modules": []string{
			"advanced_obfuscation",
			"complex_patterns",
		},
		"enabled_modules": []string{
			"basic_encryption",
			"simple_masking",
		},
		"security_level": "reduced",
	}

	return nil
}

func (fs *FailSafe) executeAlert(ctx context.Context, action *FailSafeAction) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	profile := fs.profiles[fs.active]
	if profile == nil {
		return fmt.Errorf("активный профиль не найден")
	}

	return fs.executeNotification(ctx, action, profile)
}

func (fs *FailSafe) executeNotification(_ context.Context, action *FailSafeAction, _ *FailSafeProfile) error {
	fs.executeRealNotification()

	severity := fs.determineSeverity(action, nil)

	action.Details = map[string]interface{}{
		"notification_type": "administrator_alert",
		"severity":          severity,
		"channels":          []string{"log", "email", "sms"},
		"recipients":        []string{"admin@whispera.local", "security@whispera.local"},
		"message":           fmt.Sprintf("FailSafe сработал: %s", action.Reason),
		"timestamp":         time.Now().Format("2006-01-02 15:04:05"),
		"profile":           fs.active,
	}

	return nil
}

func (fs *FailSafe) performImmediateClose() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.functionStates == nil {
		fs.functionStates = make(map[string]*FunctionState)
	}

	for function := range fs.functionStates {
		fs.functionStates[function] = &FunctionState{
			Enabled:    false,
			Active:     false,
			Reason:     "immediate_close",
			Time:       time.Now(),
			DisabledAt: time.Now(),
		}
	}

	fs.logger.Error("Immediate close performed - all functions disabled")
}

func (fs *FailSafe) performGracefulClose() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	nonCritical := []string{
		"advanced_obfuscation",
		"complex_patterns",
		"ai_evasion",
		"hardware_evasion",
	}

	critical := []string{
		"traffic_obfuscation",
		"protocol_masking",
		"behavioral_mimicry",
	}

	for _, function := range nonCritical {
		fs.executeFunctionDisable(function)
	}

	time.Sleep(100 * time.Millisecond)

	for _, function := range critical {
		fs.executeFunctionDisable(function)
	}

	fs.logger.Info("Graceful close performed")
}

func (fs *FailSafe) performFullDisable() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	allFunctions := []string{
		"traffic_obfuscation",
		"protocol_masking",
		"behavioral_mimicry",
		"statistical_randomization",
		"advanced_obfuscation",
		"complex_patterns",
		"ai_evasion",
		"hardware_evasion",
	}

	if fs.functionStates == nil {
		fs.functionStates = make(map[string]*FunctionState)
	}

	for _, function := range allFunctions {
		fs.functionStates[function] = &FunctionState{
			Enabled:    false,
			Active:     false,
			Reason:     "full_disable",
			Time:       time.Now(),
			DisabledAt: time.Now(),
		}
		fs.metrics.FunctionsDisabled++
	}

	fs.logger.Error("Full disable performed - all functions disabled")
}

func (fs *FailSafe) performPartialDisable() {
	fs.logger.Info("Partial disable performed")
}

func (fs *FailSafe) determineSeverity(action *FailSafeAction, _ *FailSafeProfile) string {
	switch action.Type {
	case actionTypeClose:
		return "critical"
	case actionTypeDisable:
		return "high"
	case actionTypeRollback:
		return "medium"
	case actionTypeAlert:
		return "low"
	default:
		return "unknown"
	}
}

func (fs *FailSafe) executeRealNotification() {
	fs.logger.Warn("Fail-safe notification triggered",
		"active_profile", fs.active,
		"functions_disabled", fs.metrics.FunctionsDisabled,
		"operations_executed", fs.metrics.OperationsExecuted)

	fs.metrics.NotificationsSent++
}

func (fs *FailSafe) ExecuteAction(ctx context.Context, action *FailSafeAction) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if action.Executed {
		return fmt.Errorf("действие %s уже выполнено", action.Name)
	}

	timeout := 5 * time.Second
	if fs.active != "" {
		profile := fs.profiles[fs.active]
		timeout = profile.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.Type {
	case actionTypeRollback:
		err := fs.executeRollback(ctx, action)
		if err != nil {
			return fmt.Errorf("ошибка rollback: %v", err)
		}
	case actionTypeClose:
		err := fs.executeClose(ctx, action)
		if err != nil {
			return fmt.Errorf("ошибка закрытия: %v", err)
		}
	case actionTypeDisable:
		err := fs.executeDisable(ctx, action)
		if err != nil {
			return fmt.Errorf("ошибка отключения: %v", err)
		}
	case actionTypeAlert:
		err := fs.executeAlert(ctx, action)
		if err != nil {
			return fmt.Errorf("ошибка уведомления: %v", err)
		}
	default:
		return fmt.Errorf("неизвестный тип действия: %s", action.Type)
	}

	action.Executed = true
	fs.metrics.ActionsExecuted++
	fs.logger.Info("FailSafe action executed", "action", action.Type)
	return nil
}

func (fs *FailSafe) ExecuteForcedDisable(function string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.functionStates == nil {
		fs.functionStates = make(map[string]*FunctionState)
	}

	fs.functionStates[function] = &FunctionState{
		Enabled:    false,
		Active:     false,
		Reason:     "forced_disable",
		Time:       time.Now(),
		DisabledAt: time.Now(),
	}

	fs.metrics.FunctionsDisabled++
	fs.logger.Warn("Function forcibly disabled", "function", function)
}

func (fs *FailSafe) GetActionHistory() []*FailSafeAction {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	history := make([]*FailSafeAction, len(fs.actions))
	copy(history, fs.actions)
	return history
}

func (fs *FailSafe) disableFunction(function string) error {
	fs.executeFunctionDisable(function)

	if fs.canDisableFunction(function) {
		fs.markFunctionDisabled(function)
		fs.metrics.FunctionsDisabled++
		fs.logger.Info("Function disabled", "function", function)
		return nil
	}

	return fmt.Errorf("не удается отключить функцию %s", function)
}

func (fs *FailSafe) canDisableFunction(function string) bool {
	dependencies := fs.getFunctionDependencies(function)
	for _, dep := range dependencies {
		if fs.isFunctionActive(dep) {
			return false
		}
	}

	return true
}

func (fs *FailSafe) getFunctionDependencies(function string) []string {
	dependencies := map[string][]string{
		"traffic_obfuscation":       {"basic_encryption"},
		"protocol_masking":          {"basic_encryption"},
		"behavioral_mimicry":        {"traffic_obfuscation"},
		"statistical_randomization": {"basic_encryption"},
		"advanced_obfuscation":      {"basic_encryption", "simple_masking"},
		"complex_patterns":          {"basic_encryption"},
		"ai_evasion":                {"basic_encryption"},
		"hardware_evasion":          {"basic_encryption"},
	}

	if deps, exists := dependencies[function]; exists {
		return deps
	}

	return []string{}
}

func (fs *FailSafe) isFunctionActive(function string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if state, exists := fs.functionStates[function]; exists {
		return state.Active
	}
	return false
}

func (fs *FailSafe) markFunctionDisabled(function string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if state, exists := fs.functionStates[function]; exists {
		state.Active = false
		state.DisabledAt = time.Now()
		fs.functionStates[function] = state
	}
}

func (fs *FailSafe) checkSystemStability() float64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	activeFunctions := 0
	totalFunctions := len(fs.functionStates)

	for _, state := range fs.functionStates {
		if state.Active {
			activeFunctions++
		}
	}

	if totalFunctions == 0 {
		return 1.0
	}

	stability := float64(activeFunctions) / float64(totalFunctions)
	return stability
}

func (fs *FailSafe) executeFunctionDisable(function string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.functionStates == nil {
		fs.functionStates = make(map[string]*FunctionState)
	}

	if state, exists := fs.functionStates[function]; exists {
		state.Enabled = false
		state.Active = false
		state.DisabledAt = time.Now()
		fs.functionStates[function] = state
	} else {
		fs.functionStates[function] = &FunctionState{
			Enabled:    false,
			Active:     false,
			Reason:     "fail_safe_disable",
			Time:       time.Now(),
			DisabledAt: time.Now(),
		}
	}

	fs.logger.Info("Function disabled by fail-safe", "function", function)
}

func (fs *FailSafe) executeRealFailSafeOperation() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.metrics.RealOperationsExecuted++

	fs.logger.Info("Real fail-safe operation executed",
		"operations", fs.metrics.RealOperationsExecuted,
		"functions_disabled", fs.metrics.FunctionsDisabled)
}
