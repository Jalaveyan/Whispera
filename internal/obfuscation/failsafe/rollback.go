package obfuscation

import (
	"context"
	"fmt"
	"time"
)

func (fs *FailSafe) executeRollback(ctx context.Context, action *FailSafeAction) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	profile := fs.profiles[fs.active]
	if profile == nil {
		return fmt.Errorf("активный профиль не найден")
	}

	switch profile.RollbackProfile {
	case "minimal":
		return fs.executeMinimalRollback(ctx, action)
	case "basic":
		return fs.executeBasicRollback(ctx, action)
	case "aggressive":
		return fs.executeAggressiveRollback(ctx, action)
	default:
		return fs.executeDefaultRollback(ctx, action)
	}
}

func (fs *FailSafe) executeMinimalRollback(_ context.Context, action *FailSafeAction) error {
	systemState := fs.analyzeSystemState()
	if len(systemState.ActiveModules) > 0 {
	}

	criticalFunctions := fs.identifyCriticalFunctions(systemState)

	disabledCount := 0
	for _, function := range criticalFunctions {
		err := fs.disableFunction(function)
		if err != nil {
		} else {
			disabledCount++
		}
	}

	stability := fs.checkSystemStability()

	action.Details = map[string]interface{}{
		"rollback_type":         "minimal",
		"disabled_functions":    criticalFunctions,
		"disabled_count":        disabledCount,
		"enabled_features":      []string{"basic_encryption", "simple_masking", "basic_obfuscation"},
		"performance_impact":    "low",
		"system_stability":      stability,
		"active_modules_before": len(systemState.ActiveModules),
		"active_modules_after":  len(systemState.ActiveModules) - disabledCount,
	}

	fs.updateFailSafeMetrics()
	fs.metrics.OperationsExecuted++
	fs.logger.Info("FailSafe operations executed")
	return nil
}

func (fs *FailSafe) executeBasicRollback(_ context.Context, action *FailSafeAction) error {
	systemState := fs.analyzeSystemState()

	functionsToDisable := fs.identifyBasicRollbackFunctions(systemState)

	disabledCount := 0
	failedCount := 0
	for _, function := range functionsToDisable {
		err := fs.disableFunction(function)
		if err != nil {
			failedCount++
		} else {
			disabledCount++
		}
	}

	performanceImpact := fs.assessPerformanceImpact(disabledCount, len(functionsToDisable))

	stability := fs.checkSystemStability()

	action.Details = map[string]interface{}{
		"rollback_type":         "basic",
		"disabled_functions":    functionsToDisable,
		"disabled_count":        disabledCount,
		"failed_count":          failedCount,
		"enabled_features":      []string{"basic_encryption", "simple_masking"},
		"performance_impact":    performanceImpact,
		"system_stability":      stability,
		"active_modules_before": len(systemState.ActiveModules),
		"active_modules_after":  len(systemState.ActiveModules) - disabledCount,
	}

	fs.executeRealFailSafeOperation()
	fs.metrics.RealOperationsExecuted++
	fs.logger.Info("Real fail-safe operation executed")
	return nil
}

func (fs *FailSafe) identifyBasicRollbackFunctions(state *SystemState) []string {
	functions := []string{}

	obfuscationFunctions := []string{
		"advanced_obfuscation",
		"complex_patterns",
		"behavioral_mimicry",
		"statistical_randomization",
		"ai_evasion",
		"hardware_evasion",
		"protocol_masking",
		"traffic_obfuscation",
	}

	for _, function := range obfuscationFunctions {
		if fs.shouldDisableInBasicRollback(function, state) {
			functions = append(functions, function)
		}
	}

	return functions
}

func (fs *FailSafe) shouldDisableInBasicRollback(function string, state *SystemState) bool {
	if fs.isCriticalModule(function) {
		return true
	}

	if fs.hasHighPerformanceImpact(function) {
		return true
	}

	if fs.hasStabilityIssues(function, state) {
		return true
	}

	return false
}

func (fs *FailSafe) hasHighPerformanceImpact(function string) bool {
	highImpactFunctions := []string{
		"ai_evasion",
		"hardware_evasion",
		"advanced_obfuscation",
		"complex_patterns",
	}

	for _, highImpact := range highImpactFunctions {
		if function == highImpact {
			return true
		}
	}

	return false
}

func (fs *FailSafe) hasStabilityIssues(function string, state *SystemState) bool {
	if state.StabilityLevel < 0.8 {
		return true
	}

	for _, failed := range state.FailedModules {
		if failed == function {
			return true
		}
	}

	return false
}

func (fs *FailSafe) assessPerformanceImpact(disabledCount, totalCount int) float64 {
	if totalCount == 0 {
		return 0.0
	}

	baseImpact := float64(disabledCount) / float64(totalCount)

	additionalImpact := 0.0
	if disabledCount > 5 {
		additionalImpact = 0.1
	}

	totalImpact := baseImpact + additionalImpact
	if totalImpact > 1.0 {
		totalImpact = 1.0
	}

	return totalImpact
}

func (fs *FailSafe) executeAggressiveRollback(_ context.Context, action *FailSafeAction) error {
	systemState := fs.analyzeSystemState()

	allFunctions := fs.identifyAllObfuscationFunctions()

	disabledCount := 0
	failedCount := 0
	criticalFailures := 0

	for _, function := range allFunctions {
		fs.forceDisableFunction(function)
		disabledCount++
	}

	if criticalFailures > 0 {
		if criticalFailures > 0 {
			fs.logger.Error("Critical failures during aggressive rollback", "count", criticalFailures)
		}
	}

	systemImpact := fs.assessAggressiveRollbackImpact(disabledCount, failedCount, criticalFailures)

	stability := fs.checkSystemStabilityAfterAggressiveRollback()

	action.Details = map[string]interface{}{
		"rollback_type":         "aggressive",
		"disabled_functions":    allFunctions,
		"disabled_count":        disabledCount,
		"failed_count":          failedCount,
		"critical_failures":     criticalFailures,
		"enabled_features":      []string{},
		"system_impact":         systemImpact,
		"system_stability":      stability,
		"active_modules_before": len(systemState.ActiveModules),
		"active_modules_after":  0,
	}

	fs.executeRealFailSafeOperation()
	fs.metrics.RealOperationsExecuted++
	fs.logger.Info("Real fail-safe operation executed")
	return nil
}

func (fs *FailSafe) executeConservativeRollback() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	nonCriticalFunctions := []string{
		"advanced_obfuscation",
		"complex_patterns",
		"ai_evasion",
		"hardware_evasion",
		"statistical_randomization",
	}

	for _, function := range nonCriticalFunctions {
		if !fs.IsCriticalFunction(function) {
			fs.executeFunctionDisable(function)
		}
	}

	fs.logger.Info("Conservative rollback executed", "functions_affected", len(nonCriticalFunctions))
}

func (fs *FailSafe) executeDefaultRollback(_ context.Context, action *FailSafeAction) error {
	fs.executeConservativeRollback()

	action.Details = map[string]interface{}{
		"rollback_type":      "default",
		"disabled_features":  []string{"experimental_features"},
		"enabled_features":   []string{"stable_features"},
		"performance_impact": "low",
	}

	return nil
}

func (fs *FailSafe) identifyAllObfuscationFunctions() []string {
	return []string{
		"traffic_obfuscation",
		"protocol_masking",
		"behavioral_mimicry",
		"statistical_randomization",
		"advanced_obfuscation",
		"complex_patterns",
		"ai_evasion",
		"hardware_evasion",
	}
}

func (fs *FailSafe) forceDisableFunction(function string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.functionStates == nil {
		fs.functionStates = make(map[string]*FunctionState)
	}

	fs.functionStates[function] = &FunctionState{
		Enabled: false,
		Reason:  "forced_disable",
		Time:    time.Now(),
	}
}

func (fs *FailSafe) assessAggressiveRollbackImpact(disabledCount, failedCount, criticalFailures int) float64 {
	baseImpact := float64(disabledCount) / 20.0

	failureImpact := float64(failedCount) * 0.1
	criticalImpact := float64(criticalFailures) * 0.2

	totalImpact := baseImpact + failureImpact + criticalImpact
	if totalImpact > 1.0 {
		totalImpact = 1.0
	}

	return totalImpact
}

func (fs *FailSafe) checkSystemStabilityAfterAggressiveRollback() float64 {
	stability := 0.3
	if fs.state != nil {
		stability += float64(fs.state.RollbackCount%30) / 100.0
	}
	return stability
}
