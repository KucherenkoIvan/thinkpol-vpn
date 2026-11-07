package localapi

import (
	"fmt"
	"log/slog"
	"os"

	"google.golang.org/grpc/grpclog"
)

// RouteGRPCLog sends grpc's own log to log, instead of grpc's default,
// which writes its errors straight to os.Stderr: under a device's service
// that is the crash trace, where they would read as a crash. Its info
// and warnings are at debug, as grpc's default leaves them out. Call it
// before the local API starts (grpclog.SetLoggerV2 isn't safe once grpc
// runs).
func RouteGRPCLog(log *slog.Logger) {
	grpclog.SetLoggerV2(grpcLogger{log: log.With("component", "grpc")})
}

// grpcLogger is a grpclog.LoggerV2 over slog.
type grpcLogger struct{ log *slog.Logger }

func (g grpcLogger) Info(args ...any)                    { g.log.Debug(fmt.Sprint(args...)) }
func (g grpcLogger) Infoln(args ...any)                  { g.log.Debug(sprintln(args...)) }
func (g grpcLogger) Infof(format string, args ...any)    { g.log.Debug(fmt.Sprintf(format, args...)) }
func (g grpcLogger) Warning(args ...any)                 { g.log.Debug(fmt.Sprint(args...)) }
func (g grpcLogger) Warningln(args ...any)               { g.log.Debug(sprintln(args...)) }
func (g grpcLogger) Warningf(format string, args ...any) { g.log.Debug(fmt.Sprintf(format, args...)) }
func (g grpcLogger) Error(args ...any)                   { g.log.Error(fmt.Sprint(args...)) }
func (g grpcLogger) Errorln(args ...any)                 { g.log.Error(sprintln(args...)) }
func (g grpcLogger) Errorf(format string, args ...any)   { g.log.Error(fmt.Sprintf(format, args...)) }
func (g grpcLogger) Fatal(args ...any)                   { g.fatal(fmt.Sprint(args...)) }
func (g grpcLogger) Fatalln(args ...any)                 { g.fatal(sprintln(args...)) }
func (g grpcLogger) Fatalf(format string, args ...any)   { g.fatal(fmt.Sprintf(format, args...)) }

// V is grpc's verbosity: 0, its default.
func (g grpcLogger) V(l int) bool { return l <= 0 }

func (g grpcLogger) fatal(msg string) {
	g.log.Error(msg)
	os.Exit(1)
}

func sprintln(args ...any) string {
	s := fmt.Sprintln(args...)
	return s[:len(s)-1]
}
