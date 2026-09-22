package inference

const mockReply = "Hello, this is a verifiable response."

// mockNoFields is what the mock answers when the caller constrains the output to a
// schema: a structurally valid object with no values in it. The mock never invents
// a field value — an extraction that returns nothing is honest about returning
// nothing, where a plausible-looking invention would not be.
const mockNoFields = `{"confidence":{},"fields":{}}`

type Mock struct{}

func NewMock() *Mock {
	return &Mock{}
}

func (m *Mock) Complete(req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = "sealed-mock"
	}
	content := mockReply
	if req.JSONSchema != "" || req.Grammar != "" {
		content = mockNoFields
	}
	return Response{
		Content: content,
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
