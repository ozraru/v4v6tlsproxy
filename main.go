package main

import (
	"context"
	"log/slog"

	"github.com/ozraru/v4v6tlsproxy/internal"
)

func main() {
	ctx := context.Background()

	if internal.Config.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	internal.Listen(ctx)
}
