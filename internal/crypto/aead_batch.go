package crypto

import (
	"sync"
)

type BatchAEADState struct {
	*AEADState
	batchBuffer []byte
	mu          sync.Mutex
}

func NewBatchAEADState(aeadState *AEADState) *BatchAEADState {
	return &BatchAEADState{
		AEADState:   aeadState,
		batchBuffer: make([]byte, 0, 65535),
	}
}

func (b *BatchAEADState) BatchEncrypt(seq uint32, aad []byte, plaintexts [][]byte) ([][]byte, error) {
	results := make([][]byte, len(plaintexts))

	if len(plaintexts) == 1 {
		ct, err := b.Encrypt(seq, aad, plaintexts[0])
		if err != nil {
			return nil, err
		}
		results[0] = ct
		return results, nil
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(plaintexts))

	for i, plaintext := range plaintexts {
		wg.Add(1)
		go func(idx int, pt []byte) {
			defer wg.Done()

			ct, err := b.Encrypt(seq+uint32(idx), aad, pt)
			if err != nil {
				errChan <- err
				return
			}
			results[idx] = ct
		}(i, plaintext)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	return results, nil
}

func (b *BatchAEADState) BatchDecrypt(seq uint32, aad []byte, ciphertexts [][]byte) ([][]byte, error) {
	results := make([][]byte, len(ciphertexts))

	if len(ciphertexts) == 1 {
		pt, err := b.Decrypt(seq, aad, ciphertexts[0])
		if err != nil {
			return nil, err
		}
		results[0] = pt
		return results, nil
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(ciphertexts))

	for i, ciphertext := range ciphertexts {
		wg.Add(1)
		go func(idx int, ct []byte) {
			defer wg.Done()
			pt, err := b.Decrypt(seq+uint32(idx), aad, ct)
			if err != nil {
				errChan <- err
				return
			}
			results[idx] = pt
		}(i, ciphertext)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	return results, nil
}

func (s *AEADState) EncryptOptimized(seq uint32, aad, plaintext []byte) ([]byte, error) {
	return s.Encrypt(seq, aad, plaintext)
}
func (s *AEADState) EncryptControl(seq uint32, aad, plaintext []byte, encrypt bool) ([]byte, error) {
	_ = encrypt
	return s.Encrypt(seq, aad, plaintext)
}

type StreamAEADState struct {
	*AEADState
	streamCounter uint64
	mu            sync.Mutex
}

func NewStreamAEADState(aeadState *AEADState) *StreamAEADState {
	return &StreamAEADState{
		AEADState:     aeadState,
		streamCounter: 0,
	}
}

var streamAAD = []byte{0x01}

func (s *StreamAEADState) EncryptStream(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	seq := uint32(s.streamCounter)
	s.streamCounter++
	s.mu.Unlock()

	return s.Encrypt(seq, streamAAD, plaintext)
}
