package main

import "testing"
import "github.com/stretchr/testify/assert"

func TestIntSet_String(t *testing.T) {
	assert.Equal(t, "1", NewIntSet(NewIntRange(1, 1)).String())
	assert.Equal(t, "1:1-2", NewIntSet(NewIntRange(1, 1), NewIntRange(1, 2)).String())
}

func TestParseIntSet(t *testing.T) {
	intRange, err := ParseIntSet("1:1-2")
	assert.NoError(t, err)
	assert.Equal(t, 1, intRange.ranges[0].Start)
	assert.Equal(t, 1, intRange.ranges[0].End)
	assert.Equal(t, 1, intRange.ranges[1].Start)
	assert.Equal(t, 2, intRange.ranges[1].End)
}
