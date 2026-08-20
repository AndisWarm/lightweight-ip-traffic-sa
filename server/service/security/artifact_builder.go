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
	baseInfoCollected, err := b.baseInfoCollector.Collect(taskID, targetIP, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("base info collect failed: %w", err)
	}

	reputationCollected, err := b.reputationCollector.Collect(targetIP, cfg)
	if err != nil {
		return TaskPipelineResult{}, fmt.Errorf("reputation collect failed: %w", err)
	}

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
