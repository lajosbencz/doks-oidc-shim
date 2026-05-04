// Package logging configures the unified slog/logr handler used across the binary.
package logging

import (
	"cmp"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	defaultLevel  = "info"
	defaultFormat = "json"
)

// SetupFromEnv configures the logger from LOG_LEVEL and LOG_FORMAT env vars
// (or built-in defaults). Call this as the first statement in main() so any
// log line emitted before flag parsing uses the operator-chosen format.
func SetupFromEnv() error {
	return Setup(
		cmp.Or(os.Getenv("LOG_LEVEL"), defaultLevel),
		cmp.Or(os.Getenv("LOG_FORMAT"), defaultFormat),
	)
}

// RegisterFlags adds --log-level and --log-format as persistent flags on cmd.
// Call this once on the root command so subcommands inherit them.
func RegisterFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("log-level", defaultLevel, "log level: debug, info, warn, error")
	cmd.PersistentFlags().String("log-format", defaultFormat, "log format: json, text")
}

// SetupFromCmd reconfigures the logger after cobra has parsed flags. Uses viper
// to apply the standard precedence: CLI flag > env var > flag default.
func SetupFromCmd(cmd *cobra.Command) error {
	v := viper.New()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	if err := v.BindPFlag("log-level", cmd.Flags().Lookup("log-level")); err != nil {
		return fmt.Errorf("binding log-level: %w", err)
	}
	if err := v.BindPFlag("log-format", cmd.Flags().Lookup("log-format")); err != nil {
		return fmt.Errorf("binding log-format: %w", err)
	}
	return Setup(v.GetString("log-level"), v.GetString("log-format"))
}

// Setup configures slog.Default and bridges controller-runtime (logr) onto the
// same handler so all logs land in one stream with one format.
func Setup(level, format string) error {
	lvl, err := parseLevel(level)
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json", "":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		return fmt.Errorf("unknown log format %q (want json or text)", format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	ctrl.SetLogger(logr.FromSlogHandler(handler))
	return nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug, info, warn, error)", s)
	}
}
