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

func (m *Mock) CompleteStream(req Request, emit TokenHandler) (Response, error) {
	out, err := m.Complete(req)
	if err != nil {
		return Response{}, err
	}
	if emit != nil && out.Content != "" {
		if err := emit(out.Content); err != nil {
			return Response{}, err
		}
	}
	return out, nil
}
