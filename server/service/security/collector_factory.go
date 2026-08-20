package security

import "lightweight-ip-traffic-sa/server/config"

// NewTaskPipelineBuilder 用于创建并返回新的业务实例。
func NewTaskPipelineBuilder(cfg config.SecurityConfig) TaskPipelineBuilder {
	return TaskPipelineBuilder{
		baseInfoCollector:      chooseBaseInfoCollector(cfg),
		reputationCollector:    chooseReputationCollector(cfg),
		attackSurfaceCollector: chooseAttackSurfaceCollector(cfg),
		flowCollector:          chooseFlowCollector(cfg),
		featureNormalizer:      DefaultFeatureNormalizer{},
		scoreCalculator:        WeightedScoreCalculator{},
		alertDecider:           ThresholdAlertDecider{},
	}
}

// chooseBaseInfoCollector 用于选择基础信息Collector。
func chooseBaseInfoCollector(cfg config.SecurityConfig) BaseInfoCollector {
	if cfg.DemoMode {
		return DemoBaseInfoCollector{}
	}
	return RealBaseInfoCollector{}
}

// chooseReputationCollector 用于选择ReputationCollector。
func chooseReputationCollector(cfg config.SecurityConfig) ReputationCollector {
	if cfg.DemoMode {
		return DemoReputationCollector{}
	}
	return RealReputationCollector{}
}

// chooseAttackSurfaceCollector 用于选择AttackSurfaceCollector。
func chooseAttackSurfaceCollector(cfg config.SecurityConfig) AttackSurfaceCollector {
	if cfg.DemoMode {
		return DemoAttackSurfaceCollector{}
	}
	return RealAttackSurfaceCollector{}
}

// chooseFlowCollector 用于选择流量Collector。
func chooseFlowCollector(cfg config.SecurityConfig) FlowCollector {
	if cfg.DemoMode {
		return DemoFlowCollector{}
	}
	return RealFlowCollector{}
}
