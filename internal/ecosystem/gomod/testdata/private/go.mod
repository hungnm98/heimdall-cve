module github.com/acme/service

go 1.22

require (
	github.com/acme/billing/v2 v2.1.0
	git.corp.example.com/team/auth v1.0.0
	github.com/acmeinc/public v1.0.0
	github.com/public/lib v1.2.0 // indirect
	github.com/google/uuid v1.6.0
)

// public module swapped for a private fork
replace github.com/public/lib => github.com/acme/lib-fork v1.2.0-acme.1
