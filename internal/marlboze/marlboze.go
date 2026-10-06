package marlboze

import (
	"time"

	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/marlboze"
)

func Init() {
	marlboze.Log = app.GetLogger("marlboze")
	streams.HandleFunc("marlboze", func(source string) (core.Producer, error) {
		started := time.Now()
		producer, err := marlboze.Dial(source)
		if err != nil {
			marlboze.Log.Warn().Err(err).Dur("elapsed_ms", time.Since(started)).Msg("[marlboze] connection failed")
		}
		return producer, err
	})
}
