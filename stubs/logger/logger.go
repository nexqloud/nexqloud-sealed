package logger

import "io"

func Init(_ string, _, _ bool, _ io.Writer) {}

func Warning(_ ...interface{}) {}

func Warningf(_ string, _ ...interface{}) {}

func Errorf(_ string, _ ...interface{}) {}

func Fatal(_ ...interface{}) {}

func Fatalf(_ string, _ ...interface{}) {}
