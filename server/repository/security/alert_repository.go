package security

import (
	"errors"
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"

	"gorm.io/gorm"
)

// AlertRepository 用于封装安全态势模块的数据持久化访问。
type AlertRepository struct{}

// AlertListRow 用于承载预警List数据库查询行。
type AlertListRow struct {
	ID          uint64
	TaskNo      string
	IP          string
	SourceType  string
	SourceLabel string
	AlertLevel  string
	Channel     string
	SendStatus  string
	CreatedAt   time.Time
}

// AlertDailyCountRow 用于承载预警DailyCount数据库查询行。
type AlertDailyCountRow struct {
	Date  string
	Count int64
}

// AlertDetailBundle 用于聚合预警Detail详情查询所需数据。
type AlertDetailBundle struct {
	Alert *securityModel.AlertRecord
	Task  *securityModel.IPTask
	Score *securityModel.RiskScore
}

// Create 用于写入预警记录。
func (r *AlertRepository) Create(db *gorm.DB, alert *securityModel.AlertRecord) error {
	return db.Create(alert).Error
}

// FindByID 用于查询预警记录。
func (r *AlertRepository) FindByID(db *gorm.DB, alertID uint64) (*securityModel.AlertRecord, error) {
	var alert securityModel.AlertRecord
	err := db.Where("id = ?", alertID).First(&alert).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &alert, nil
}

// FindByTaskID 用于查询预警记录。
func (r *AlertRepository) FindByTaskID(db *gorm.DB, taskID uint64) (*securityModel.AlertRecord, error) {
	var alert securityModel.AlertRecord
	err := db.Where("task_id = ?", taskID).Order("id DESC").First(&alert).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &alert, nil
}

// FindDetailByID 组装预警详情：实时监控产生的预警 task_id 为 NULL/0（不绑定任务），
// 因此这里先判空再决定是否回查任务与评分，避免对不存在的任务误查。
// FindDetailByID 用于查询预警记录。
func (r *AlertRepository) FindDetailByID(db *gorm.DB, alertID uint64) (*AlertDetailBundle, error) {
	alert, err := r.FindByID(db, alertID)
	if err != nil {
		return nil, err
	}
	if alert == nil {
		return nil, nil
	}

	var task *securityModel.IPTask
	if alert.TaskID != nil && *alert.TaskID != 0 {
		taskValue, err := (&TaskRepository{}).FindByID(db, *alert.TaskID)
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
		} else {
			task = &taskValue
		}
	}

	var score *securityModel.RiskScore
	if alert.TaskID != nil && *alert.TaskID != 0 {
		score, err = (&ScoreRepository{}).FindByTaskID(db, *alert.TaskID)
		if err != nil {
			return nil, err
		}
	}

	return &AlertDetailBundle{
		Alert: alert,
		Task:  task,
		Score: score,
	}, nil
}

// List 分页查询预警列表：LEFT JOIN 任务表以带出 task_no 并按发起人过滤；
// source_type/source_label 为空时用 COALESCE 动态推导——有 task_id 视为 TASK，否则视为 FLOW_MONITOR。
// List 用于查询预警列表。
func (r *AlertRepository) List(db *gorm.DB, query requestModel.AlertListQuery) ([]AlertListRow, int64, error) {
	base := db.Table("sec_alert_record AS a").
		Joins("LEFT JOIN sec_ip_task AS t ON t.id = a.task_id")

	if query.CreatedBy != "" {
		base = base.Where("t.created_by = ?", query.CreatedBy)
	}

	if query.TargetIP != "" {
		base = base.Where("a.ip = ?", query.TargetIP)
	}
	if query.AlertLevel != "" {
		base = base.Where("a.alert_level = ?", query.AlertLevel)
	}
	if query.SendStatus != "" {
		base = base.Where("a.send_status = ?", query.SendStatus)
	}
	if query.Channel != "" {
		base = base.Where("a.channel = ?", query.Channel)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []AlertListRow
	err := base.Select("a.id, t.task_no, a.ip, COALESCE(NULLIF(a.source_type, ''), CASE WHEN a.task_id IS NULL THEN 'FLOW_MONITOR' ELSE 'TASK' END) AS source_type, COALESCE(NULLIF(a.source_label, ''), COALESCE(t.task_no, a.ip)) AS source_label, a.alert_level, a.channel, a.send_status, a.created_at").
		Order("a.created_at DESC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Scan(&rows).Error

	return rows, total, err
}

// CountAll 用于统计预警数据。
func (r *AlertRepository) CountAll(db *gorm.DB) (int64, error) {
	var count int64
	if err := db.Model(&securityModel.AlertRecord{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountDailyTrend 用于统计预警数据。
func (r *AlertRepository) CountDailyTrend(db *gorm.DB, start time.Time) ([]AlertDailyCountRow, error) {
	var rows []AlertDailyCountRow
	err := db.Model(&securityModel.AlertRecord{}).
		Select("DATE_FORMAT(created_at, '%Y-%m-%d') AS date, COUNT(*) AS count").
		Where("created_at >= ?", start).
		Group("DATE_FORMAT(created_at, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 按任务批量删除预警，属于删除任务时的级联清理步骤之一。
// DeleteByTaskID 用于删除预警记录。
func (r *AlertRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.AlertRecord{}).Error
}
