package response

// Envelope 是所有接口的统一响应信封：Code=0 表示成功、Code=1 表示业务失败，
// Data 承载具体业务数据，与前端约定的统一返回结构保持一致。
// Envelope 用于映射Envelope数据库记录。
type Envelope struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// Ok 构造成功响应信封（Code=0），Message 固定为 "success"，业务数据放入 Data。
// Ok 用于执行Ok流程。
func Ok(data interface{}) Envelope {
	return Envelope{
		Code:    0,
		Message: "success",
		Data:    data,
	}
}

// Fail 构造失败响应信封（Code=1），把业务错误文案透出给前端展示。
// Fail 用于执行Fail流程。
func Fail(message string) Envelope {
	return Envelope{
		Code:    1,
		Message: message,
		Data:    nil,
	}
}
