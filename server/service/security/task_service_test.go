package security

import (
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
)

func TestBuildTaskNoIsUniqueWithinSameTimestamp(t *testing.T) {
	now := time.Date(2026, 6, 7, 14, 53, 27, 0, time.UTC)
	seen := make(map[string]struct{}, 100)

	for i := 0; i < 100; i++ {
		taskNo := buildTaskNo(now)
		if _, exists := seen[taskNo]; exists {
			t.Fatalf("buildTaskNo generated duplicate task number %q", taskNo)
		}
		seen[taskNo] = struct{}{}
	}
}

func TestCreateTaskWithActorReturnsRunningBeforePipelineCompletes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		Conn:                      db,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}

	previousDB := global.DB
	previousConfig := global.AppConfig
	global.DB = gormDB
	global.AppConfig = config.ServerConfig{
		Security: config.SecurityConfig{
			DemoMode:         true,
			DefaultCreatedBy: "admin",
		},
	}
	defer func() {
		global.DB = previousDB
		global.AppConfig = previousConfig
	}()

	pipelineStarted := make(chan struct{}, 1)
	releasePipeline := make(chan struct{})
	previousExecutor := taskPipelineAsyncExecutor
	taskPipelineAsyncExecutor = func(task securityTaskExecutionContext) {
		pipelineStarted <- struct{}{}
		<-releasePipeline
	}
	defer func() {
		taskPipelineAsyncExecutor = previousExecutor
		close(releasePipeline)
	}()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO `sec_ip_task`")).
		WithArgs(
			sqlArgAnyString{},
			"IP",
			"8.8.8.8",
			"8.8.8.8",
			"alice",
			"PENDING",
			"",
			nil,
			nil,
			sqlArgAnyTime{},
			sqlArgAnyTime{},
		).
		WillReturnResult(sqlmock.NewResult(42, 1))
	mock.ExpectCommit()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE `sec_ip_task`")).
		WithArgs(
			"",
			sqlArgAnyTime{},
			"RUNNING",
			sqlArgAnyTime{},
			uint64(42),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	resp, err := (&TaskService{}).CreateTaskWithActor(requestModel.CreateTaskRequest{
		TargetIP: "8.8.8.8",
	}, "alice")
	if err != nil {
		t.Fatalf("CreateTaskWithActor() error = %v", err)
	}

	if resp.TaskID != 42 {
		t.Fatalf("TaskID = %d, want 42", resp.TaskID)
	}
	if resp.TaskStatus != "RUNNING" {
		t.Fatalf("TaskStatus = %q, want RUNNING", resp.TaskStatus)
	}
	if resp.ScoreValue != 0 {
		t.Fatalf("ScoreValue = %.2f, want 0 before background scoring", resp.ScoreValue)
	}
	if resp.RiskLevel != "" {
		t.Fatalf("RiskLevel = %q, want empty before background scoring", resp.RiskLevel)
	}

	select {
	case <-pipelineStarted:
	case <-time.After(time.Second):
		t.Fatal("background pipeline was not scheduled")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

type sqlArgAnyTime struct{}

func (sqlArgAnyTime) Match(value driver.Value) bool {
	_, ok := value.(time.Time)
	return ok
}

type sqlArgAnyString struct{}

func (sqlArgAnyString) Match(value driver.Value) bool {
	_, ok := value.(string)
	return ok
}
