module github.com/example/replace

go 1.22

require (
	github.com/old/lib v1.2.0
	github.com/local/thing v0.3.0
	github.com/any/ver v1.5.0
	github.com/pinned/only v1.1.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// module -> module, versionless left side: applies to every version
replace github.com/old/lib => github.com/new/lib v1.3.1

// local path
replace github.com/local/thing => ../thing

replace github.com/any/ver v1.5.0 => github.com/fork/ver v1.5.1-patched

// versioned left side that does not match the required version: not applied
replace github.com/pinned/only v1.0.0 => github.com/fork/only v1.0.1

// the versioned replace wins over the versionless one for the same module
replace (
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v2 v2.4.0 => gopkg.in/yaml.v2 v2.4.1
)
