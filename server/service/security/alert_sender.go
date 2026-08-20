package security

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// sendAlertByConfiguredChannel 用于发送通知、告警或外部请求。
func sendAlertByConfiguredChannel(decision *AlertDecision, cfg config.SecurityConfig) (string, *time.Time, error) {
	if decision == nil {
		return "SKIPPED", nil, nil
	}

	channel := strings.ToUpper(strings.TrimSpace(decision.Channel))
	// 默认 SYSTEM 通道不接第三方通知服务，只记审计日志并返回发送成功，
	// 保证预警链路不因外部通知服务缺失而失败。
	if channel == "" || channel == "SYSTEM" {
		now := time.Now()
		recordSecurityAuditLog(AuditLogEntry{
			Category:    "ALERT",
			Action:      "SEND_ALERT",
			TargetType:  "alert-channel",
			TargetID:    fallbackString(channel, "SYSTEM"),
			TargetLabel: decision.Title,
			Status:      "SUCCESS",
			Summary:     "系统内预警已写入",
		})
		return "SUCCESS", &now, nil
	}

	if channel == "SYSTEM+MAIL" || channel == "MAIL" {
		return sendAlertMail(decision, cfg)
	}

	now := time.Now()
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "ALERT",
		Action:      "SEND_ALERT",
		TargetType:  "alert-channel",
		TargetID:    channel,
		TargetLabel: decision.Title,
		Status:      "SUCCESS",
		Summary:     "已按默认通道记录预警",
	})
	return "SUCCESS", &now, nil
}

// sendAlertMail 用于发送通知、告警或外部请求。
func sendAlertMail(decision *AlertDecision, cfg config.SecurityConfig) (string, *time.Time, error) {
	mailCfg := cfg.Alert.Mail
	to := strings.TrimSpace(mailCfg.Recipient)

	// 邮件未启用/配置不完整都返回明确的 FAILED/SKIPPED 状态并记审计，
	// 上层据此把预警记录标记为发送失败，而不是静默丢失。
	if !mailCfg.Enabled {
		recordAlertMailAudit(to, decision.Title, "SKIPPED", "邮件预警未启用")
		return "SKIPPED", nil, fmt.Errorf("mail alert disabled")
	}

	addr := fmt.Sprintf("%s:%d", strings.TrimSpace(mailCfg.SMTPHost), mailCfg.SMTPPort)
	from := strings.TrimSpace(mailCfg.Sender)
	if from == "" || to == "" || strings.TrimSpace(mailCfg.SMTPHost) == "" {
		recordAlertMailAudit(to, decision.Title, "FAILED", "邮件预警配置不完整")
		return "FAILED", nil, fmt.Errorf("mail alert configuration incomplete")
	}

	message := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, decision.Title, decision.Content))
	if mailCfg.UseTLS {
		// InsecureSkipVerify 跳过证书校验，适配内网/自签名 SMTP 环境；
		// 生产环境若对外网 SMTP 应关闭该选项以避免中间人风险。
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: mailCfg.SMTPHost, InsecureSkipVerify: true})
		if err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		client, err := smtp.NewClient(conn, mailCfg.SMTPHost)
		if err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		if strings.TrimSpace(mailCfg.Username) != "" {
			auth := smtp.PlainAuth("", mailCfg.Username, mailCfg.Password, mailCfg.SMTPHost)
			if err := client.Auth(auth); err != nil {
				recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
				return "FAILED", nil, err
			}
		}
		if err := client.Mail(from); err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		if err := client.Rcpt(to); err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		writer, err := client.Data()
		if err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		if _, err := writer.Write(message); err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
		_ = writer.Close()
		_ = client.Quit()
	} else {
		var auth smtp.Auth
		if strings.TrimSpace(mailCfg.Username) != "" {
			auth = smtp.PlainAuth("", mailCfg.Username, mailCfg.Password, mailCfg.SMTPHost)
		}
		if err := smtp.SendMail(addr, auth, from, []string{to}, message); err != nil {
			recordAlertMailAudit(to, decision.Title, "FAILED", err.Error())
			return "FAILED", nil, err
		}
	}

	now := time.Now()
	recordAlertMailAudit(to, decision.Title, "SUCCESS", "邮件预警发送成功")
	return "SUCCESS", &now, nil
}

// recordAlertMailAudit 用于记录预警Mail审计。
func recordAlertMailAudit(target string, title string, status string, summary string) {
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "ALERT",
		Action:      "SEND_ALERT_MAIL",
		TargetType:  "mail",
		TargetID:    target,
		TargetLabel: title,
		Status:      status,
		Summary:     summary,
	})
}
