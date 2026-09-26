# CryptoProvider

[English](../en/CRYPTO.md) | Русский

Статус: контракт зафиксирован, набор c25519 реализован и проходит providertest. Набор ГОСТ
в работе.

## Операции

| Операция | ГОСТ (crypto/gost) | Сравнительный (crypto/c25519) |
|---|---|---|
| Эфемерная пара | ГОСТ Р 34.10-2012, 256 бит, paramSetA (TC26) | X25519 |
| Согласование | VKO ГОСТ Р 34.10-2012 (Р 50.1.113-2016), с UKM | X25519 |
| KDF | KDF_GOSTR3411_2012_256 (Р 50.1.113-2016) | HKDF-SHA-256 |
| AEAD | Кузнечик-MGM (Р 1323565.1.026-2019), nonce 16 байт, тег 16 | XChaCha20-Poly1305, nonce 24, тег 16 |
| Подпись | ГОСТ Р 34.10-2012, 256 бит | Ed25519 |
| Хэш | Стрибог-256 | SHA-256 |

Различие размеров nonce и накладных расходов видно через интерфейс: wire не хардкодит размеры.

## Интерфейс

```go
type Suite uint8

type CryptoProvider interface {
	Suite() Suite

	GenerateEphemeral() (priv *secmem.Buffer, pub []byte, err error)
	Agree(priv *secmem.Buffer, peerPub, ukm []byte) (*secmem.Buffer, error)
	DeriveKey(secret *secmem.Buffer, label []byte, size int) (*secmem.Buffer, error)
	KeySize() int

	NewAEAD(key *secmem.Buffer) (AEAD, error)

	GenerateSigning() (priv *secmem.Buffer, pub []byte, err error)
	Sign(priv *secmem.Buffer, msg []byte) ([]byte, error)
	Verify(pub, msg, sig []byte) bool

	Hash(data ...[]byte) []byte
}

type AEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	// Destroy zeroes the expanded key schedule the cipher holds.
	Destroy()
}
```

Принятые решения:
- Секреты пересекают границу интерфейса только как *secmem.Buffer. Открытые ключи и подписи
  это []byte: они не секретны, а типизация на каждый набор усложнила бы wire.
- ukm обязателен и для обоих наборов: он привязывает общий секрет к сессии. В ГОСТ это штатный
  параметр VKO, в c25519 подаётся как salt HKDF.
- KeySize отдаёт длину ключа AEAD, чтобы wire не хардкодил 32 байта.
- Nonce назначает wire: провайдер их не хранит и не считает. Повтор nonce под одним ключом
  исключается форматом ячейки. В 16-байтном nonce старший бит всегда нулевой, как требует MGM:
  первым идёт счётчик с направлением, случайный идентификатор цепочки последним.
- GenerateSigning выдаёт долговременную пару для аутентификации узла, отдельно от эфемерной.

## Работа с памятью (crypto/secmem)

- Буфер выделяется через mmap вне кучи Go, mlock, madvise(MADV_DONTDUMP).
- Release: зануление, munlock, munmap. Двойной Release не паникует.
- Процесс: prctl(PR_SET_DUMPABLE, 0), RLIMIT_CORE=0.
- В контейнере mlock ограничен RLIMIT_MEMLOCK. Считать бюджет буферов, при нехватке отказ старта.
- PR_SET_DUMPABLE=0 закрывает ptrace и /proc/pid/mem для того же uid. Это пересекается со
  сценарием С1: мера "запрет дампов" должна включаться переключателем.

## Кандидаты библиотек

- ГОСТ: go.cypherpunks.su/gogost (GPLv3, проверить актуальный путь модуля и наличие KDF и MGM).
- c25519: golang.org/x/crypto (curve25519, chacha20poly1305, hkdf). Подпись Ed25519 по RFC 8032
  на filippo.io/edwards25519, прямо над буфером secmem. crypto/ed25519 начиная с Go 1.25 кэширует
  развёрнутый ключ по слабому указателю на ключ: на памяти mmap рантайм аварийно завершается, а на
  куче развёрнутый ключ живёт до сборки мусора.

## Известные дыры

- Шифры разворачивают ключ в раундовые ключи на куче Go (Кузнечик, ChaCha state). Их зануление
  зависит от библиотеки, GC может копировать. Фиксируется в LIMITATIONS.md.
- X25519 через crypto/ecdh копирует скаляр в кучу на время вызова, эту копию занулить нельзя.
  Состояние SHA-512 при подписи тоже на куче и на время вызова держит префикс nonce, по
  чувствительности равный ключу. Внутренняя копия скаляра в edwards25519 не зануляется.
