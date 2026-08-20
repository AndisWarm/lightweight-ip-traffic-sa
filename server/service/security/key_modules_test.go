package security

import (
	"errors"
	"testing"

	"lightweight-ip-traffic-sa/server/config"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	"lightweight-ip-traffic-sa/server/utils"
)

func TestValidateCreateTaskRequestCoversIPAndInvalidInputs(t *testing.T) {
	resolved, err := validateCreateTaskRequest(requestModel.CreateTaskRequest{TargetIP: " 8.8.8.8 "})
	if err != nil {
		t.Fatalf("validateCreateTaskRequest(valid IP) error = %v", err)
	}
	if resolved.InputType != "IP" || resolved.InputValue != "8.8.8.8" || resolved.TargetIP != "8.8.8.8" {
		t.Fatalf("resolved target = %+v, want normalized IP target", resolved)
	}

	_, err = validateCreateTaskRequest(requestModel.CreateTaskRequest{TargetIP: " "})
	if !errors.Is(err, ErrTaskTargetIPRequired) {
		t.Fatalf("empty target error = %v, want ErrTaskTargetIPRequired", err)
	}

	_, err = validateCreateTaskRequest(requestModel.CreateTaskRequest{TargetIP: "bad_domain"})
	if !errors.Is(err, ErrTaskTargetIPInvalid) {
		t.Fatalf("invalid target error = %v, want ErrTaskTargetIPInvalid", err)
	}

	_, err = validateCreateTaskRequest(requestModel.CreateTaskRequest{TargetIP: "missing-host.invalid"})
	if !errors.Is(err, ErrTaskDomainResolveFailed) {
		t.Fatalf("unresolvable domain error = %v, want ErrTaskDomainResolveFailed", err)
	}
}

func TestTaskListQueryNormalizeAndValidate(t *testing.T) {
	query := requestModel.TaskListQuery{
		TargetIP:   " 8.8.8.8 ",
		TaskStatus: " success ",
		RiskLevel:  " high ",
	}
	query.Normalize()

	if query.TargetIP != "8.8.8.8" || query.TaskStatus != "SUCCESS" || query.RiskLevel != "HIGH" {
		t.Fatalf("normalized query = %+v", query)
	}
	if query.SortBy != "createdAt" || query.SortOrder != "desc" {
		t.Fatalf("default sort = %s/%s, want createdAt/desc", query.SortBy, query.SortOrder)
	}
	if err := query.Validate(); err != nil {
		t.Fatalf("Validate(valid query) error = %v", err)
	}

	invalidStatus := query
	invalidStatus.TaskStatus = "DONE"
	if err := invalidStatus.Validate(); err == nil {
		t.Fatal("Validate(invalid status) expected error")
	}

	invalidSortBy := query
	invalidSortBy.SortBy = "updatedAt"
	if err := invalidSortBy.Validate(); err == nil {
		t.Fatal("Validate(invalid sortBy) expected error")
	}

	invalidSortOrder := query
	invalidSortOrder.SortOrder = "sideways"
	if err := invalidSortOrder.Validate(); err == nil {
		t.Fatal("Validate(invalid sortOrder) expected error")
	}
}

func TestRiskFeatureHelpersCoverBoundaries(t *testing.T) {
	whoisRisk := computeWhoisRiskFromCollected(BaseInfoCollectedData{
		Country: "RU",
		ISP:     "Cloud Hosting",
	})
	if whoisRisk != 70 {
		t.Fatalf("whoisRisk = %.2f, want 70", whoisRisk)
	}

	attackRisk := computeAttackSurfaceRiskFromCollected(AttackSurfaceCollectedData{
		OpenPortCount:     30,
		HighRiskPortCount: 10,
		GeoRiskFlag:       true,
	})
	if attackRisk != 100 {
		t.Fatalf("attackRisk = %.2f, want cap 100", attackRisk)
	}

	for _, tc := range []struct {
		name string
		raw  float64
		want float64
	}{
		{name: "negative", raw: -1, want: 0},
		{name: "upper cap", raw: 150, want: 100},
		{name: "round", raw: 42.129, want: 42.13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := computeBehaviorRisk(FlowCollectedData{BehaviorRiskScore: tc.raw})
			if got != tc.want {
				t.Fatalf("computeBehaviorRisk() = %.2f, want %.2f", got, tc.want)
			}
		})
	}
}

func TestWeightedScoreAndAlertDecisionCoverThresholdsAndRuleCap(t *testing.T) {
	cfg := baseSecurityTestConfig()
	normalized := NormalizedFeatureSet{
		WhoisRiskScore:    70,
		ReputationScore:   80,
		AttackSurfaceRisk: 65,
		BehaviorRisk:      80,
		GeoRiskFlag:       true,
		HighRiskPortCount: 3,
		FlowMode:          "sample",
		FlowStatus:        "PARSED",
		FlowParsedMetrics: map[string]any{"packetCount": 10},
		SourceSummary:     "GeoLite2 -> RDAP",
		ScoreFactors: []securityScoreFactor{
			{Key: "whois", Contribution: 14},
			{Key: "reputation", Contribution: 28},
			{Key: "attack_surface", Contribution: 20},
			{Key: "behavior", Contribution: 10},
		},
	}

	score, err := WeightedScoreCalculator{}.Calculate(7, "8.8.8.8", normalized, cfg)
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	if score.RuleAdjustmentValue != 15 {
		t.Fatalf("RuleAdjustmentValue = %.2f, want capped 15", score.RuleAdjustmentValue)
	}
	if score.ScoreValue != 87 || score.RiskLevel != "HIGH" || !score.IsAlertTriggered {
		t.Fatalf("score = %+v, want score 87 HIGH alert", score)
	}

	decision, err := ThresholdAlertDecider{}.Decide(7, "TASK-1", "8.8.8.8", score, cfg)
	if err != nil {
		t.Fatalf("Decide(alert) error = %v", err)
	}
	if decision == nil || !decision.ShouldAlert || decision.AlertLevel != "HIGH" || decision.Channel != "SYSTEM" {
		t.Fatalf("decision = %+v, want HIGH SYSTEM alert", decision)
	}

	score.IsAlertTriggered = false
	decision, err = ThresholdAlertDecider{}.Decide(7, "TASK-1", "8.8.8.8", score, cfg)
	if err != nil {
		t.Fatalf("Decide(no alert) error = %v", err)
	}
	if decision != nil {
		t.Fatalf("decision = %+v, want nil when alert is not triggered", decision)
	}
}

func TestRuleAdjustmentReliefAndRiskLevelBoundaries(t *testing.T) {
	cfg := baseSecurityTestConfig()
	relief := calculateRuleAdjustmentValue(NormalizedFeatureSet{
		BehaviorRisk: 5,
		FlowMode:     "disabled",
	}, cfg)
	if relief != -2 {
		t.Fatalf("relief adjustment = %.2f, want -2", relief)
	}

	for _, tc := range []struct {
		score float64
		want  string
	}{
		{score: 44.99, want: "LOW"},
		{score: 45, want: "MEDIUM"},
		{score: 75, want: "HIGH"},
		{score: 90, want: "CRITICAL"},
	} {
		got := mapRiskLevel(tc.score, cfg)
		if got != tc.want {
			t.Fatalf("mapRiskLevel(%.2f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestValidateConfigRequestCoversWeightsFlowAndMail(t *testing.T) {
	valid := validUpdateConfigRequest()
	if err := validateConfigRequest(valid); err != nil {
		t.Fatalf("validateConfigRequest(valid) error = %v", err)
	}

	badWeight := valid
	badWeight.Weights.BehaviorWeight = 0.14
	if err := validateConfigRequest(badWeight); err == nil {
		t.Fatal("validateConfigRequest(bad weight sum) expected error")
	}

	badMail := valid
	badMail.MailEnabled = true
	badMail.SMTPHost = ""
	badMail.MailRecipient = "ops@example.test"
	if err := validateConfigRequest(badMail); err == nil {
		t.Fatal("validateConfigRequest(mail without SMTP host) expected error")
	}

	badAttackSurface := valid
	badAttackSurface.AttackSurfaceEndpoint = "full-port-scan"
	if err := validateConfigRequest(badAttackSurface); err == nil {
		t.Fatal("validateConfigRequest(unsupported attack surface endpoint) expected error")
	}
}

func TestFlowMonitorScoreTuningAlertAndPermissions(t *testing.T) {
	cfg := baseSecurityTestConfig()
	benignWebMetrics := map[string]any{
		"httpHostHints": []map[string]any{{"key": "example.test", "count": 6}},
		"portDensityIndicators": map[string]any{
			"uniqueTargetPortCount":   3,
			"highRiskTargetPortCount": 0,
		},
		"scanScore":      20.0,
		"burstScore":     20.0,
		"httpEventCount": 6,
	}

	adjusted, summary := normalizeFlowMonitorBehaviorScore(80, benignWebMetrics)
	if adjusted != 32 {
		t.Fatalf("benign adjusted score = %.2f, want 32", adjusted)
	}
	if summary == "" {
		t.Fatal("benign adjustment summary should explain the downgrade")
	}
	if shouldTriggerFlowMonitorAlert(80, benignWebMetrics, cfg) {
		t.Fatal("benign web traffic without strong signal should not trigger alert")
	}

	strongMetrics := map[string]any{
		"scanScore": 70.0,
		"portDensityIndicators": map[string]any{
			"highRiskTargetPortCount": 2,
		},
	}
	adjusted, _ = normalizeFlowMonitorBehaviorScore(80, strongMetrics)
	if adjusted != 80 {
		t.Fatalf("strong adjusted score = %.2f, want unchanged 80", adjusted)
	}
	if !shouldTriggerFlowMonitorAlert(80, strongMetrics, cfg) {
		t.Fatal("strong high-score flow signal should trigger alert")
	}

	state := &flowMonitorSessionState{OwnerUserID: 10}
	if err := ensureFlowMonitorSessionReadable(state, nil); err == nil {
		t.Fatal("nil claims should not read flow monitor session")
	}
	if err := ensureFlowMonitorSessionReadable(state, &utils.TokenClaims{UserID: 10, RoleCode: "USER"}); err != nil {
		t.Fatalf("owner read error = %v", err)
	}
	if err := ensureFlowMonitorSessionReadable(state, &utils.TokenClaims{UserID: 11, RoleCode: "USER"}); err == nil {
		t.Fatal("different USER should not read another user's session")
	}
	if err := ensureFlowMonitorSessionReadable(state, &utils.TokenClaims{UserID: 11, RoleCode: "MANAGER"}); err != nil {
		t.Fatalf("manager read error = %v", err)
	}
	if err := ensureFlowMonitorSessionWritable(state, &utils.TokenClaims{UserID: 11, RoleCode: "MANAGER"}); err == nil {
		t.Fatal("manager should not stop another user's session")
	}
	if err := ensureFlowMonitorSessionWritable(state, &utils.TokenClaims{UserID: 11, RoleCode: "ADMIN"}); err != nil {
		t.Fatalf("admin write error = %v", err)
	}
}

func baseSecurityTestConfig() config.SecurityConfig {
	return config.SecurityConfig{
		HighRiskThreshold:     75,
		CriticalRiskThreshold: 90,
		Alert: config.AlertConfig{
			NotifyChannel: "SYSTEM",
		},
		Weights: config.WeightConfig{
			WhoisWeight:         0.20,
			ReputationWeight:    0.35,
			AttackSurfaceWeight: 0.30,
			BehaviorWeight:      0.15,
		},
	}
}

func validUpdateConfigRequest() requestModel.UpdateConfigRequest {
	return requestModel.UpdateConfigRequest{
		WhoisEndpoint:         "local-demo",
		ReputationEndpoint:    "local-blacklist",
		AttackSurfaceEndpoint: "limited-port-scan",
		FlowMode:              "sample",
		FlowWindowSeconds:     5,
		FlowTimeoutSeconds:    7,
		NotifyChannel:         "SYSTEM",
		HighRiskThreshold:     75,
		CriticalRiskThreshold: 90,
		Weights: requestModel.ConfigWeightRequest{
			WhoisWeight:         0.20,
			ReputationWeight:    0.35,
			AttackSurfaceWeight: 0.30,
			BehaviorWeight:      0.15,
		},
	}
}
