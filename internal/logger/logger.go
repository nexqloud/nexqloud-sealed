// Drop-in for github.com/google/logger so go-sev-guest compiles on js/wasm.
package logger

import (
	"io"
	"os"
)

type Level int

type Logger struct{}

type Verbose struct{}

func Init(_ string, _, _ bool, _ io.Writer) *Logger { return &Logger{} }

func Close() {}

func (l *Logger) Close() {}

func SetFlags(_ int) {}

func SetLevel(_ Level) {}

func (l *Logger) SetLevel(_ Level) {}

func V(_ Level) Verbose { return Verbose{} }

func (l *Logger) V(_ Level) Verbose { return Verbose{} }

func (Verbose) Info(...interface{})                   {}
func (Verbose) Infoln(...interface{})                {}
func (Verbose) Infof(string, ...interface{})        {}

func Info(...interface{})                   {}
func InfoDepth(int, ...interface{})         {}
func Infoln(...interface{})                 {}
func Infof(string, ...interface{})          {}
func (*Logger) Info(...interface{})        {}
func (*Logger) InfoDepth(int, ...interface{}) {}
func (*Logger) Infoln(...interface{})      {}
func (*Logger) Infof(string, ...interface{}) {}

func Warning(...interface{})                {}
func WarningDepth(int, ...interface{})    {}
func Warningln(...interface{})            {}
func Warningf(string, ...interface{})     {}
func (*Logger) Warning(...interface{})    {}
func (*Logger) WarningDepth(int, ...interface{}) {}
func (*Logger) Warningln(...interface{})  {}
func (*Logger) Warningf(string, ...interface{}) {}

func Error(...interface{})              {}
func ErrorDepth(int, ...interface{})    {}
func Errorln(...interface{})            {}
func Errorf(string, ...interface{})     {}
func (*Logger) Error(...interface{})    {}
func (*Logger) ErrorDepth(int, ...interface{}) {}
func (*Logger) Errorln(...interface{})  {}
func (*Logger) Errorf(string, ...interface{}) {}

func Fatal(...interface{})              { os.Exit(1) }
func FatalDepth(int, ...interface{})    { os.Exit(1) }
func Fatalln(...interface{})            { os.Exit(1) }
func Fatalf(string, ...interface{})     { os.Exit(1) }
func (*Logger) Fatal(...interface{})    { os.Exit(1) }
func (*Logger) FatalDepth(int, ...interface{}) { os.Exit(1) }
func (*Logger) Fatalln(...interface{})  { os.Exit(1) }
func (*Logger) Fatalf(string, ...interface{}) { os.Exit(1) }
