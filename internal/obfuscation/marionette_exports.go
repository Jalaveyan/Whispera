package obfuscation

import (
	mariomethods "whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
)

type MarionetteAdapter = mariomethods.MarionetteAdapter

func NewMarionetteAdapter() *MarionetteAdapter {
	return mariomethods.NewMarionetteAdapter()
}

type Marionette = mariomethods.Marionette

type UnifiedMLSystem = mlpkg.UnifiedMLSystem
