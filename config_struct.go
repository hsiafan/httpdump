package main

import (
	"errors"
	"strconv"
	"strings"
)

// parse int set
func ParseIntSet(str string) (*IntSet, error) {
	if str == "" {
		return nil, errors.New("empty str")
	}
	var intSet IntSet
	for _, item := range strings.Split(str, ":") {
		var numbers = strings.Split(item, "-")
		if len(numbers) > 2 {
			return nil, errors.New("illegal range str: " + item)
		}
		if len(numbers) == 1 {
			start, err := strconv.Atoi(numbers[0])
			if err != nil {
				return nil, err
			}
			intSet.ranges = append(intSet.ranges, NewIntRange(start, start))
		} else if len(numbers) == 2 {
			start, err := strconv.Atoi(numbers[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(numbers[1])
			if err != nil {
				return nil, err
			}
			intSet.ranges = append(intSet.ranges, NewIntRange(start, end))
		}
	}
	return &intSet, nil
}

// A set of int values
type IntSet struct {
	ranges []IntRange
}

// Create new IntSet
func NewIntSet(ranges ...IntRange) *IntSet {
	return &IntSet{
		ranges: ranges,
	}
}

// implement Stringer
func (s *IntSet) String() string {
	var sb strings.Builder
	for index, r := range s.ranges {
		if index > 0 {
			sb.WriteRune(':')
		}
		if r.Start == r.End {
			sb.WriteString(strconv.Itoa(r.Start))
		} else {
			sb.WriteString(strconv.Itoa(r.Start))
			sb.WriteRune('-')
			sb.WriteString(strconv.Itoa(r.End))
		}
	}
	return sb.String()
}

// If this set contains int value
func (s *IntSet) Contains(value int) bool {
	for _, r := range s.ranges {
		if r.Contains(value) {
			return true
		}
	}
	return false
}

// Range of int value
type IntRange struct {
	Start int // inclusive
	End   int // inclusive
}

// Create new int range
func NewIntRange(start int, end int) IntRange {
	return IntRange{
		Start: start,
		End:   end,
	}
}

// If this range contains the value
func (r *IntRange) Contains(value int) bool {
	return value >= r.Start && value <= r.End
}
