package inference

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Response struct {
	Content string
	Model   string
}

type Backend interface {
	Complete(req Request) (Response, error)
}
