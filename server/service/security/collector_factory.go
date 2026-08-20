package security

import "lightweight-ip-traffic-sa/server/config"

// NewTaskPipelineBuilder 用于创建并返回新的业务实例。
func NewTaskPipelineBuilder(cfg config.SecurityConfig) TaskPipelineBuilder {
	// 流水线在这里完成装配：采集器按 DemoMode 二选一，归一化/评分/预警决策固定用默认实现，
	// 后续替换评分算法只需改这一处，采集与展示层无感知。
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
	// DemoMode 下用本地演示数据，避免依赖外部数据源与网络；否则走真实采集链路。
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
