package security

import (
	"errors"
	"fmt"
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"

	"gorm.io/gorm"
)

// TaskRepository 用于封装安全态势模块的数据持久化访问。
type TaskRepository struct{}

// TaskListRow 用于承载任务List数据库查询行。
type TaskListRow struct {
	ID         uint64
	TaskNo     string
	InputType  string
	InputValue string
	TargetIP   string
	TaskStatus string
	ScoreValue float64
	RiskLevel  string
	CreatedAt  time.Time
}

// TaskSummary 用于承载任务摘要汇总结果。
type TaskSummary struct {
	TotalTasks      int64
	TodayDetections int64
}

// DailyCountRow 用于承载DailyCount数据库查询行。
type DailyCountRow struct {
	Date  string
	Count int64
}

// TaskDetailBundle 用于聚合任务Detail详情查询所需数据。
type TaskDetailBundle struct {
	Task           *securityModel.IPTask
	BaseInfo       *securityModel.IPBaseInfo
	Feature        *securityModel.FeatureSnapshot
	Score          *securityModel.RiskScore
	Alert          *securityModel.AlertRecord
	FlowCollection *securityModel.FlowCollection
	FlowWindows    []securityModel.FlowWindowAggregate
	FlowFeature    *securityModel.FlowFeatureSnapshot
}

// Create 用于写入任务记录。
func (r *TaskRepository) Create(db *gorm.DB, task *securityModel.IPTask) error {
	return db.Create(task).Error
}

// FindByID 用于查询任务记录。
func (r *TaskRepository) FindByID(db *gorm.DB, taskID uint64) (securityModel.IPTask, error) {
	var task securityModel.IPTask
	err := db.Where("id = ?", taskID).First(&task).Error
	return task, err
}

// FindDetailByID 聚合 7 个仓储查询组装任务详情（画像/特征/评分/预警/流量采集/窗口/流量特征）。
// 任务不存在时返回 (nil, nil)，上层据此区分“查无此任务”与“数据库异常”；若本次采集没有流量特征，
// 回退到按 task_id 取最近一次流量特征快照，保证详情页流量块不为空。
// FindDetailByID 用于查询任务记录。
func (r *TaskRepository) FindDetailByID(db *gorm.DB, taskID uint64) (*TaskDetailBundle, error) {
	task, err := r.FindByID(db, taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	baseInfo, err := (&BaseInfoRepository{}).FindByTaskID(db, taskID)
	if err != nil {
		return nil, err
	}
	feature, err := (&FeatureRepository{}).FindByTaskID(db, taskID)
	if err != nil {
		return nil, err
	}
	score, err := (&ScoreRepository{}).FindByTaskID(db, taskID)
	if err != nil {
		return nil, err
	}
	alert, err := (&AlertRepository{}).FindByTaskID(db, taskID)
	if err != nil {
		return nil, err
	}
	flowCollection, err := (&FlowCollectionRepository{}).FindLatestByTaskID(db, taskID)
	if err != nil {
		return nil, err
	}
	var flowWindows []securityModel.FlowWindowAggregate
	if flowCollection != nil {
		flowWindows, err = (&FlowWindowAggregateRepository{}).ListByCollectionID(db, flowCollection.ID, 0)
		if err != nil {
			return nil, err
		}
	}
	var flowFeature *securityModel.FlowFeatureSnapshot
	if flowCollection != nil {
		flowFeature, err = (&FlowFeatureSnapshotRepository{}).FindByCollectionID(db, flowCollection.ID)
		if err != nil {
			return nil, err
		}
	}
	if flowFeature == nil {
		flowFeature, err = (&FlowFeatureSnapshotRepository{}).FindLatestByTaskID(db, taskID)
		if err != nil {
			return nil, err
		}
	}

	return &TaskDetailBundle{
		Task:           &task,
		BaseInfo:       baseInfo,
		Feature:        feature,
		Score:          score,
		Alert:          alert,
		FlowCollection: flowCollection,
		FlowWindows:    flowWindows,
		FlowFeature:    flowFeature,
	}, nil
}

// UpdateStatus 用于更新任务记录。
func (r *TaskRepository) UpdateStatus(db *gorm.DB, taskID uint64, fields map[string]interface{}) error {
	return db.Model(&securityModel.IPTask{}).
		Where("id = ?", taskID).
		Updates(fields).Error
}

// DeleteByID 硬删除单条任务。GORM 默认不带外键级联，关联的画像/特征/评分/预警等子表
// 必须由 service 层在事务中依次显式删除，否则会产生孤儿数据。
// DeleteByID 用于删除任务记录。
func (r *TaskRepository) DeleteByID(db *gorm.DB, taskID uint64) error {
	return db.Where("id = ?", taskID).Delete(&securityModel.IPTask{}).Error
}

// List 分页查询任务列表：LEFT JOIN 评分表把分值/风险等级一并带出，避免列表页 N+1 查询；
// 条件按需拼接（target_ip 模糊、status/risk_level 精确），COALESCE 兜底未评分任务按 LOW 参与筛选；
// 先 Count 取总数再 Limit/Offset 取当页。分页与排序参数已在 request 层做过白名单校验，此处可直接拼接。
// List 用于查询任务列表。
func (r *TaskRepository) List(db *gorm.DB, query requestModel.TaskListQuery) ([]TaskListRow, int64, error) {
	base := db.Table("sec_ip_task AS t").
		Joins("LEFT JOIN sec_risk_score AS r ON r.task_id = t.id")

	if query.TargetIP != "" {
		base = base.Where("t.target_ip LIKE ?", "%"+query.TargetIP+"%")
	}
	if query.TaskStatus != "" {
		base = base.Where("t.task_status = ?", query.TaskStatus)
	}
	if query.RiskLevel != "" {
		base = base.Where("COALESCE(r.risk_level, 'LOW') = ?", query.RiskLevel)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	orderExpr := buildTaskListOrder(query.SortBy, query.SortOrder)
	var rows []TaskListRow
	err := base.Select(
		"t.id, t.task_no, t.input_type, t.input_value, t.target_ip, t.task_status, t.created_at, COALESCE(r.score_value, 0) AS score_value, COALESCE(r.risk_level, 'LOW') AS risk_level",
	).
		Order(orderExpr).
		Order("t.id DESC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Scan(&rows).Error

	return rows, total, err
}

// buildTaskListOrder 把前端排序字段映射为 SQL 排序表达式。sortBy/sortOrder 已在上层 Validate 做过白名单校验，
// 因此这里用 fmt.Sprintf 拼接不会引入 SQL 注入；riskLevel 用 CASE WHEN 映射为数值等级，
// 让 CRITICAL/HIGH/MEDIUM/LOW 按严重程度而非字典序排序。
// buildTaskListOrder 用于构建任务ListOrder。
func buildTaskListOrder(sortBy string, sortOrder string) string {
	switch sortBy {
	case "scoreValue":
		return fmt.Sprintf("COALESCE(r.score_value, 0) %s", sortOrder)
	case "riskLevel":
		return fmt.Sprintf(`CASE COALESCE(r.risk_level, 'LOW')
			WHEN 'CRITICAL' THEN 4
			WHEN 'HIGH' THEN 3
			WHEN 'MEDIUM' THEN 2
			ELSE 1
		END %s`, sortOrder)
	default:
		return fmt.Sprintf("t.created_at %s", sortOrder)
	}
}

// CountSummary 统计任务总量与当日新增量：dayStart 为今日零点，created_at >= dayStart 即计入“今日检测”。
// CountSummary 用于统计任务数据。
func (r *TaskRepository) CountSummary(db *gorm.DB, dayStart time.Time) (TaskSummary, error) {
	var summary TaskSummary

	if err := db.Model(&securityModel.IPTask{}).Count(&summary.TotalTasks).Error; err != nil {
		return summary, err
	}

	if err := db.Model(&securityModel.IPTask{}).
		Where("created_at >= ?", dayStart).
		Count(&summary.TodayDetections).Error; err != nil {
		return summary, err
	}

	return summary, nil
}

// CountDailyTrend 按天分桶统计任务创建量：用 DATE_FORMAT 把 created_at 归一到天粒度后 GROUP BY，
// 供总览页绘制 7/30 天趋势曲线。
// CountDailyTrend 用于统计任务数据。
func (r *TaskRepository) CountDailyTrend(db *gorm.DB, start time.Time) ([]DailyCountRow, error) {
	var rows []DailyCountRow
	err := db.Model(&securityModel.IPTask{}).
		Select("DATE_FORMAT(created_at, '%Y-%m-%d') AS date, COUNT(*) AS count").
		Where("created_at >= ?", start).
		Group("DATE_FORMAT(created_at, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}
