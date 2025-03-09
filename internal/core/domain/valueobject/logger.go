package valueobject

import (
	"go.uber.org/zap"
)

var log *zap.Logger

func init() {
	var err error
	log, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
}
