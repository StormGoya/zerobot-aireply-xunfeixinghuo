package aireply

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	ctrl "github.com/FloatTech/zbpctrl"
	"github.com/FloatTech/zbputils/control"
	"github.com/FloatTech/zbputils/ctxext"
	zero "github.com/wdvxdr1123/ZeroBot"
	"github.com/wdvxdr1123/ZeroBot/message"
)

const (
	// 请替换为你的实际 APPID, APIKey, APISecret
	appID     = ""
	apiKey    = ""
	apiSecret = ""
)

func init() { // 插件主体
	enr := control.AutoRegister(&ctrl.Options[*zero.Ctx]{
		DisableOnDefault:  false,
		Brief:             "人工智能回复",
		Help:              "- @Bot 任意文本(任意一句话回复)\n- xx 任意文本(任意一句话回复)",  //xx为 触发词+句子  可以调成自己的机器人名
		PrivateDataFolder: "aireply",
	})

	customFilter := func(ctx *zero.Ctx) bool {
		if zero.OnlyToMe(ctx) {
			return true
		}
		return strings.HasPrefix(ctx.ExtractPlainText(), "xx")//xx为 触发词+句子  可以调成自己的机器人名
	}

	enr.OnMessage(customFilter).SetBlock(true).Limit(ctxext.LimitByUser).
		Handle(func(ctx *zero.Ctx) {
			userInput := ctx.ExtractPlainText()

			if strings.HasPrefix(userInput, "xx") {  //xx为 触发词+句子  可以调成自己的机器人名
				userInput = strings.TrimSpace(userInput[len("xx"):])//xx为 触发词+句子  可以调成自己的机器人名
			}

			reply, err := getIFlyTekReply(userInput)
			if err != nil {
				ctx.SendChain(message.Reply(ctx.Event.MessageID), message.Text("ERROR: "+err.Error()))
				return
			}
			ctx.SendChain(message.Reply(ctx.Event.MessageID), message.Text(reply))
		})
}

func getIFlyTekReply(userInput string) (string, error) {
	parameter := map[string]interface{}{
		"header": map[string]string{
			"app_id": appID,
		},
		"parameter": map[string]interface{}{
			"chat": map[string]interface{}{
				"domain":      "4.0Ultra", // 根据官方文档设置正确的 domain
				"temperature": 0.5,
				"max_tokens":  8192,
				"top_k":       5,
			},
		},
		"payload": map[string]interface{}{
			"message": map[string]interface{}{
				"text": []map[string]string{
					{
						"role":    "system",
						"content": "  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  //这里为机器人的人设
					},
					{
						"role":    "user",
						"content": userInput,
					},
				},
			},
		},
	}

	// 将参数转换为 JSON
	requestJSON, err := json.Marshal(parameter)
	if err != nil {
		return "", fmt.Errorf("请求参数编码失败: %v", err)
	}

	// 生成鉴权 URL
	wsURL, err := generateAuthURL(apiKey, apiSecret, "wss://spark-api.xf-yun.com/v4.0/chat")
	if err != nil {
		return "", fmt.Errorf("生成鉴权 URL 失败: %v", err)
	}

	// 建立 WebSocket 连接
	dialer := websocket.DefaultDialer

	// 如果需要跳过证书验证（仅用于测试环境，生产环境不建议）
	// dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	var resp *http.Response
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			fmt.Printf("Handshake failed with status %d\n", resp.StatusCode)
			fmt.Printf("Response headers: %v\n", resp.Header)
		}
		return "", fmt.Errorf("连接 WebSocket 失败: %v", err)
	}
	defer conn.Close()

	// 发送请求参数
	err = conn.WriteMessage(websocket.TextMessage, requestJSON)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}

	// 接收响应
	var replyContent string
	for {
		_, messageData, err := conn.ReadMessage()
		if err != nil {
			return "", fmt.Errorf("读取响应失败: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(messageData, &response); err != nil {
			return "", fmt.Errorf("解析响应失败: %v", err)
		}

		// 处理响应数据
		if header, ok := response["header"].(map[string]interface{}); ok {
			if code, ok := header["code"].(float64); ok && code != 0 {
				return "", fmt.Errorf("请求错误: %v", header["message"])
			}
		}
		if payload, ok := response["payload"].(map[string]interface{}); ok {
			if choices, ok := payload["choices"].(map[string]interface{}); ok {
				if status, ok := choices["status"].(float64); ok && int(status) == 2 {
					// 处理最终回复
					if texts, ok := choices["text"].([]interface{}); ok {
						for _, textItem := range texts {
							if textMap, ok := textItem.(map[string]interface{}); ok {
								if content, ok := textMap["content"].(string); ok {
									replyContent += content
								}
							}
						}
					}
					break
				} else {
					// 处理中间回复
					if texts, ok := choices["text"].([]interface{}); ok {
						for _, textItem := range texts {
							if textMap, ok := textItem.(map[string]interface{}); ok {
								if content, ok := textMap["content"].(string); ok {
									replyContent += content
								}
							}
						}
					}
				}
			}
		}
	}

	if replyContent == "" {
		return "", fmt.Errorf("未收到有效的回复")
	}

	return replyContent, nil
}
func generateAuthURL(apiKey, apiSecret, gptURL string) (string, error) {
	parsedURL, err := url.Parse(gptURL)
	if err != nil {
		return "", err
	}

	host := parsedURL.Host
	path := parsedURL.Path

	// 生成时间戳
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")

	// 拼接签名字符串
	signatureOrigin := fmt.Sprintf("host: %s\ndate: %s\nGET %s HTTP/1.1", host, date, path)

	// 进行 HMAC-SHA256 加密
	h := hmac.New(sha256.New, []byte(apiSecret))
	h.Write([]byte(signatureOrigin))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 生成 Authorization 字段
	authorizationOrigin := fmt.Sprintf("api_key=\"%s\", algorithm=\"hmac-sha256\", headers=\"host date request-line\", signature=\"%s\"", apiKey, signature)
	authorization := base64.StdEncoding.EncodeToString([]byte(authorizationOrigin))

	// 组合鉴权参数
	v := url.Values{}
	v.Add("authorization", authorization)
	v.Add("date", date)
	v.Add("host", host)

	// 拼接完整的 URL
	wsURL := fmt.Sprintf("%s?%s", gptURL, v.Encode())
	return wsURL, nil
}
