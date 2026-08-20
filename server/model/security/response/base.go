package response

// Envelope 用于映射Envelope数据库记录。
type Envelope struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// Ok 用于执行Ok流程。
func Ok(data interface{}) Envelope {
	return Envelope{
		Code:    0,
		Message: "success",
		Data:    data,
	}
}

// Fail 用于执行Fail流程。
func Fail(message string) Envelope {
	return Envelope{
		Code:    1,
		Message: message,
		Data:    nil,
	}
}
