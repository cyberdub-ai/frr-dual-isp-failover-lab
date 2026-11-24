# frr-dual-isp-failover-lab

> **Воспроизводимый лабораторный стенд отказоустойчивого Linux-шлюза с двумя провайдерами на FRRouting (`BGP + BFD`, переключение за `0,9 сек`), жёсткой защитой от утечки транзита и zero-dependency Python-аудитором конфигов (`frr_failover_audit`).**

![Архитектура отказоустойчивого Linux-шлюза FRRouting BGP + BFD](docs/architecture_ru.png)

## Зачем нужен этот репозиторий
- **3-маршрутизаторный Docker-стенд FRRouting 10.2** (`edge-gw` AS 65010 ↔ `isp1-primary` AS 65100 + `isp2-backup` AS 65200) с профилем **BFD `300ms × 3` (`900ms`)**, **Local Preference `200/100`**, **AS-Path Prepend `2×`**, **RFC 8212 `bgp ebgp-requires-policy`**, **Anti-Transit `prefix-list`**, **`maximum-prefix`** и якорем **`Null0`**.
- **Скрипт живой инъекции «тихого обрыва»** (`scripts/verify_failover.sh`) с замером реального времени переключения без физического `link-down`.
- **Аудитор конфигов `frr_failover_audit`** на чистом Python 3.11+ (`0` внешних зависимостей): проверяет **10 боевых инвариантов** до выката конфига в прод и запускается в GitHub Actions CI.

## Быстрый старт (без `pip install`)

```bash
git clone https://github.com/cyberdub-ai/frr-dual-isp-failover-lab.git
cd frr-dual-isp-failover-lab

python -m frr_failover_audit lint configs/edge-gw
python -m frr_failover_audit simulate
python -m unittest discover -s tests -v
```

English documentation: [README.md](README.md) · Автор: Алексей Жуйков ([cyberdub.su](https://cyberdub.su))
