package security

// RepositoryGroup 聚合安全域下的全部仓储实例（任务/画像/特征/流量/评分/预警/配置/记录/审计）。
// RepositoryGroup 用于聚合系统域与安全域的数据访问实例。
type RepositoryGroup struct {
	TaskRepository                TaskRepository
	BaseInfoRepository            BaseInfoRepository
	FeatureRepository             FeatureRepository
	FlowCollectionRepository      FlowCollectionRepository
	FlowWindowAggregateRepository FlowWindowAggregateRepository
	FlowFeatureSnapshotRepository FlowFeatureSnapshotRepository
	ScoreRepository               ScoreRepository
	AlertRepository               AlertRepository
	ConfigRepository              ConfigRepository
	RecordRepository              RecordRepository
	AuditRepository               AuditRepository
}
