# eBPF NetMon

Курсовой проект: **eBPF-агент пассивного мониторинга TCP/UDP-соединений** и классификации (атрибуции) сетевого трафика по процессам в Linux.

## Возможности (MVP+)

- Пассивный перехват TCP: `connect` (IPv4/IPv6), `accept`, `close`
- UDP `sendmsg` / `recvmsg` с оценкой байт и агрегацией потоков
- Привязка к процессу: `pid`, `tgid`, `comm` + кэш `sock → owner`
- Фильтр loopback (`--no-loopback`)
- Агрегация статистики по процессу в userspace
- Вывод в CLI (текст / JSON lines)

Сборка и запуск — **только на Linux** (ядро ≥ 5.15, желательно с BTF).

## Структура

```
ebpf-netmon/
├── bpf/                 # eBPF-программы (ядро)
│   └── netmon.bpf.c
├── include/             # общие структуры событий
│   └── netmon.h
├── src/                 # userspace-агент
│   ├── main.c
│   ├── agent.c
│   └── agent.h
├── scripts/
│   ├── setup_deps_ubuntu.sh
│   ├── gen_vmlinux.sh
│   └── demo.sh
├── Makefile
└── README.md
```

## Зависимости (Ubuntu 22.04+)

```bash
sudo ./scripts/setup_deps_ubuntu.sh
./scripts/gen_vmlinux.sh
```

Нужны: `clang`, `llvm`, `libbpf-dev`, `linux-tools` / `bpftool`, заголовки ядра, `make`, `pkg-config`.

## Сборка

```bash
make
```

Артефакты: `build/netmon.bpf.o`, `build/netmon.skel.h`, бинарник `bin/netmon`.

## Запуск

```bash
sudo ./bin/netmon                 # текстовый вывод событий
sudo ./bin/netmon --json          # JSON lines
sudo ./bin/netmon --stats 5       # сводка по процессам каждые 5 с
sudo ./bin/netmon --no-loopback   # без 127.0.0.0/8 и ::1
```

Остановка: `Ctrl+C`.

## Демо для защиты

```bash
sudo ./scripts/demo.sh
```

Скрипт поднимает простой TCP/UDP трафик и показывает, что агент видит процессы.

## Архитектура

```
[Kernel]
  kprobe/fentry (TCP/UDP)
       → BPF maps + ring buffer events
[Userspace agent]
  libbpf load/attach → ringbuf callback
       → таблица процессов / CLI
```

Подробности hook-точек и формата событий — в `include/netmon.h` и комментариях в `bpf/netmon.bpf.c`.

## Ограничения

- Нужны привилегии (`CAP_BPF` / root)
- Видны метаданные соединений, не payload TLS
- Короткоживущие процессы: возможен PID reuse
- Контейнеры/netns — этап расширения

## Лицензия

Учебный код; при публикации укажите лицензию (например MIT) по требованиям вуза.
