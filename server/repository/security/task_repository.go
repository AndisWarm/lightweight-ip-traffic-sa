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

// DeleteByID 用于删除任务记录。
func (r *TaskRepository) DeleteByID(db *gorm.DB, taskID uint64) error {
	return db.Where("id = ?", taskID).Delete(&securityModel.IPTask{}).Error
}

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
