module github.com/example/exclude

go 1.22

require (
	github.com/excluded/mod v1.4.0
	github.com/kept/mod v1.1.0
)

exclude (
	github.com/excluded/mod v1.4.0
	github.com/kept/mod v1.0.0
)
