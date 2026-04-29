# mobile-aar

Минимальный wrapper вокруг mihomo как Go package, собирается через
`gomobile bind` в `mihomo.aar` для Android.

## Сборка

```bash
cd mobile-aar
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android/arm64 -androidapi=24 -o mihomo.aar .
```

Результат: `mihomo.aar` — Java/Kotlin импортируется как `com.whispera.mobile.Mobile`.

## API

```kotlin
import whispera.mobile.Mobile

// Запуск с TUN-fd (от VpnService.Builder.establish().fd) и yaml-конфигом.
// Конфиг должен содержать tun.device: fd://__FD__ (placeholder заменим на fd).
Mobile.start(fd, configYaml)

// Стоп: закрывает TUN, прокси, остальное.
Mobile.stop()
```

## Status

**Skeleton.** Первый build почти наверняка упадёт из-за зависимостей mihomo
которые не gomobile-friendly (cgo на linux-only headers, etc). Будем
итеративно урезать чтобы AAR хотя бы скомпилился.

## CI

В `.github/workflows/release.yml` добавлен job `build-mihomo-aar` который
запускает gomobile bind и кладёт результат в release assets.
