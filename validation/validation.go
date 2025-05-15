package validation

type Validator interface {
	ValidateContent(contentKey []byte, content []byte) error
}
