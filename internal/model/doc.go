// Package model holds Heimdall's plain data types.
//
// It is the innermost layer: it must not import any other internal package,
// so every port and adapter can depend on it without cycles.
package model
