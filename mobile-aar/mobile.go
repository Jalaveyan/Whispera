// Package mobile предоставляет минимальный API для Android VpnService:
// принять TUN-fd от Builder.establish() и mihomo-config (yaml string),
// запустить mihomo внутри текущего процесса (без subprocess), стоп.
//
// Собирается в `mihomo.aar` через `gomobile bind -target=android/arm64`.
//
// Java-сторона:
//   import com.whispera.mobile.Mobile
//   Mobile.start(fd, configYaml)
//   Mobile.stop()
package mobile

import (
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

var (
	mu      sync.Mutex
	running bool
)

// Start парсит yaml-конфиг (с `tun.device: fd://N`), стартует mihomo
// in-process. Возвращает ошибку если конфиг невалиден или старт фейлит.
func Start(fd int, configYaml string) error {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return fmt.Errorf("already running")
	}
	// Подменяем device на переданный fd, чтобы вызывающая сторона не
	// формировала строку с fd сама.
	cfgYaml := injectFd(configYaml, fd)
	cfg, err := config.Parse([]byte(cfgYaml))
	if err != nil {
		return fmt.Errorf("config parse: %w", err)
	}
	executor.ApplyConfig(cfg, true)
	running = true
	log.Infoln("[whisp-mobile] mihomo started fd=%d", fd)
	return nil
}

// Stop останавливает mihomo (закрывает TUN, прокси, etc).
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	executor.Shutdown()
	running = false
	log.Infoln("[whisp-mobile] mihomo stopped")
}

// IsRunning возвращает текущий статус для UI.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

func injectFd(yaml string, fd int) string {
	// Дешёвая замена placeholder'ом '__FD__'. Caller-side подставляет
	// 'device: fd://__FD__' в config, мы тут на конкретный номер.
	placeholder := "__FD__"
	out := make([]byte, 0, len(yaml)+8)
	for i := 0; i < len(yaml); {
		if i+len(placeholder) <= len(yaml) && yaml[i:i+len(placeholder)] == placeholder {
			out = append(out, []byte(fmt.Sprintf("%d", fd))...)
			i += len(placeholder)
		} else {
			out = append(out, yaml[i])
			i++
		}
	}
	return string(out)
}
