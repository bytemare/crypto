// Package group exposes simple and abstract operations to group Elements and Scalars.
package group

const (
	// DstMinLength is the minimum acceptable length of input DST.
	DstMinLength = 0

	// DstRecommendedMinLength is the minimum recommended length of input DST.
	DstRecommendedMinLength = 16
)

// Group abstracts operations in elliptic-curve prime-order groups.
type Group interface {
	// NewScalar returns a new, empty, scalar.
	NewScalar() Scalar

	// NewElement returns a new, empty, element.
	NewElement() Element

	// ElementLength returns the byte size of an encoded element.
	ElementLength() int

	// Identity returns the group's identity element.
	Identity() Element

	// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
	HashToGroup(input ...[]byte) Element

	// HashToScalar allows arbitrary input to be safely mapped to the field.
	HashToScalar(input ...[]byte) Scalar

	// Base returns the group's base point a.k.a. canonical generator.
	Base() Element

	// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
	MultBytes(scalar, element []byte) (Element, error)

	// DST returns the domain separation tag the group has been instantiated with.
	DST() string
}
