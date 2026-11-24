module github.com/acme/mono/services/worker

go 1.21

require (
	github.com/sirupsen/logrus v1.9.0
	github.com/hibiken/asynq v0.24.1
	github.com/redis/go-redis/v9 v9.3.0 // indirect
)

// overridden by the go.work replace
replace github.com/sirupsen/logrus => ../../third_party/logrus
