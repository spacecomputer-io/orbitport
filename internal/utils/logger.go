package utils

import (
	logging "github.com/ipfs/go-log"
)

type Logger = logging.ZapEventLogger

func GetLogger(namespace string) *Logger {
	return logging.Logger(namespace)
}
