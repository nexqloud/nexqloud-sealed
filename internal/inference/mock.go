package inference

const mockReply = "Hello, this is a verifiable response."

type Mock struct{}

func NewMock() *Mock {
	return &Mock{}
}

func (m *Mock) Complete(req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = "sealed-mock"
	}
	return Response{
		Content: mockReply,
		Model:   model,
	}, nil
}
