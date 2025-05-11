package validation

type Validation interface {
	ValidationContent(contentKey []byte, content []byte) error
}
