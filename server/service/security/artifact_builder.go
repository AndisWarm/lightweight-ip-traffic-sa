package security

import (
	"fmt"

	"lightweight-ip-traffic-sa/server/config"
)

// TaskPipelineBuilder 用于承载任务PipelineBuilder数据。
type TaskPipelineBuilder struct {
	baseInfoCollector      BaseInfoCollector
	reputationCollector    ReputationCollector
	attackSurfaceCollector AttackSurfaceCollector
	flowCollector          FlowCollector
	featureNormalizer      FeatureNormalizer
	scoreCalculator        ScoreCalculator
	alertDecider           AlertDecider
}

// Build 用于构建当前。
func (b TaskPipelineBuilder) Build(taskID uint64, taskNo string, targetIP string, cfg config.SecurityConfig) (TaskPipelineResult, error) {
	// 主链路编排：采集四维数据 → 归一化 → 加权评分 → 预警决策 → 转成落库模型。
	// 每步失败都会用 %w 包住错误向上抛，最终由调用方把任务标记为 FAILED。
	baseInfoCollected, err := b.baseInfoCollector.Collect(taskID, targetIP, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("base info collect failed: %w", err)
	}

	reputationCollected, err := b.reputationCollector.Collect(targetIP, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("reputation collect failed: %w", err)
	}

	// 攻击面采集依赖基础画像（如地理风险标记），所以把上一步结果作为入参传入。
	attackSurfaceCollected, err := b.attackSurfaceCollector.Collect(targetIP, baseInfoCollected, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("attack surface collect failed: %w", err)
	}

	flowCollected, err := b.flowCollector.Collect(targetIP, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("flow collect failed: %w", err)
	}

	collected := TaskCollectedData{
		BaseInfo:      baseInfoCollected,
		Reputation:    reputationCollected,
		AttackSurface: attackSurfaceCollected,
		Flow:          flowCollected,
	}

	normalized, err := b.featureNormalizer.Normalize(targetIP, collected, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("feature normalize failed: %w", err)
	}

	scoreResult, err := b.scoreCalculator.Calculate(taskID, targetIP, normalized, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("score calculate failed: %w", err)
	}

	alertDecision, err := b.alertDecider.Decide(taskID, taskNo, targetIP, scoreResult, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("alert decision failed: %w", err)
	}

	// 评分先转模型（拿到自增主键），预警模型再引用该主键；预警发送副作用发生在 toAlertRecordModel 内。
	scoreModel := toRiskScoreModel(taskID, targetIP, scoreResult)
	alertModel := toAlertRecordModel(taskID, targetIP, scoreModel.ID, alertDecision)

	return TaskPipelineResult{
		BaseInfo:          toBaseInfoModel(taskID, baseInfoCollected),
		FeatureSnapshot:   toFeatureSnapshotModel(taskID, normalized),
		RiskScore:         scoreModel,
		AlertRecord:       alertModel,
		FlowCollection:    toFlowCollectionModel(taskID, cfg, flowCollected),
		FlowWindows:       toFlowWindowAggregateModels(taskID, cfg, flowCollected),
		FlowFeature:       toFlowFeatureSnapshotModel(taskID, flowCollected, normalized),
		NormalizedFeature: normalized,
	}, nil
}
