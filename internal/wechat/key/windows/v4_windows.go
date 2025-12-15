package windows

import (
	"context"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	MEM_PRIVATE = 0x20000
	MaxWorkers  = 8
)

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	// 即使状态是offline（未登录），也允许尝试
	// 因为用户可能在获取密钥过程中登录微信
	if proc.Status == model.StatusOffline {
		log.Info().Msg("微信进程存在但未登录，将尝试获取密钥，请登录微信后操作")
		// 不返回错误，继续执行
	}

	// Open process handle
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, proc.PID)
	if err != nil {
		return "", "", errors.OpenProcessFailed(err)
	}
	defer windows.CloseHandle(handle)

	// 设置总超时时间：60秒
	// 这给用户足够的时间去打开图片
	timeout := time.After(60 * time.Second)
	scanRound := 0

	for {
		scanRound++
		// Create context to control all goroutines for THIS round
		scanCtx, cancel := context.WithCancel(ctx)
		
		// 记录提示日志
		if scanRound == 1 || scanRound % 5 == 0 {
			msg := fmt.Sprintf("正在进行第 %d 轮内存扫描... 请打开任意图片以触发密钥加载", scanRound)
			log.Info().Msg(msg)
			if e.logger != nil {
				e.logger.LogInfo(msg)
			}
		}

		// Create channels for memory data and results
		memoryChannel := make(chan []byte, 100)
		resultChannel := make(chan [2]string, 1)

		// Determine number of worker goroutines
		workerCount := runtime.NumCPU()
		if workerCount < 2 {
			workerCount = 2
		}
		if workerCount > MaxWorkers {
			workerCount = MaxWorkers
		}

		// Start consumer goroutines
		var workerWaitGroup sync.WaitGroup
		workerWaitGroup.Add(workerCount)
		for index := 0; index < workerCount; index++ {
			go func() {
				defer workerWaitGroup.Done()
				e.worker(scanCtx, handle, memoryChannel, resultChannel)
			}()
		}

		// Start producer goroutine
		var producerWaitGroup sync.WaitGroup
		producerWaitGroup.Add(1)
		go func() {
			defer producerWaitGroup.Done()
			defer close(memoryChannel) // Close channel when producer is done
			err := e.findMemory(scanCtx, handle, memoryChannel)
			if err != nil {
				log.Err(err).Msg("Failed to find memory regions")
			}
		}()

		// Wait for producer and consumers to complete IN BACKGROUND
		// We need this to close resultChannel
		go func() {
			producerWaitGroup.Wait()
			workerWaitGroup.Wait()
			close(resultChannel)
		}()

		// Wait for result of THIS round
		var roundImgKey string
		var roundDone bool

		for !roundDone {
			select {
			case <-ctx.Done():
				cancel()
				return "", "", ctx.Err()
			case <-timeout:
				cancel()
				return "", "", fmt.Errorf("获取图片密钥超时(60秒)，请确保已打开图片")
			case result, ok := <-resultChannel:
				if !ok {
					// Channel closed, round finished
					roundDone = true
					break
				}
				// Found something?
				if result[1] != "" {
					roundImgKey = result[1]
					// Found it!
					cancel()
					return "", roundImgKey, nil
				}
			}
		}
		
		cancel() // Ensure cleanup of this round

		// If we are here, round finished but no key found.
		// Wait a bit before next round
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-timeout:
			return "", "", fmt.Errorf("获取图片密钥超时(60秒)，请确保已打开图片")
		case <-time.After(1 * time.Second):
			// Continue to next round
		}
	}
}

// findMemoryV4 searches for writable memory regions for V4 version
func (e *V4Extractor) findMemory(ctx context.Context, handle windows.Handle, memoryChannel chan<- []byte) error {
	// Define search range
	minAddr := uintptr(0x10000)    // Process space usually starts from 0x10000
	maxAddr := uintptr(0x7FFFFFFF) // 32-bit process space limit

	if runtime.GOARCH == "amd64" {
		maxAddr = uintptr(0x7FFFFFFFFFFF) // 64-bit process space limit
	}
	log.Debug().Msgf("Scanning memory regions from 0x%X to 0x%X", minAddr, maxAddr)

	currentAddr := minAddr

	for currentAddr < maxAddr {
		var memInfo windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(handle, currentAddr, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		// Skip small memory regions
		if memInfo.RegionSize < 1024*1024 {
			currentAddr += uintptr(memInfo.RegionSize)
			continue
		}

		// Check if memory region is readable and private (Matching Dart logic)
		// Dart: _isReadableProtect check (Not NOACCESS, Not GUARD)
		isReadable := (memInfo.Protect&windows.PAGE_NOACCESS) == 0 && (memInfo.Protect&windows.PAGE_GUARD) == 0
		if memInfo.State == windows.MEM_COMMIT && isReadable && memInfo.Type == MEM_PRIVATE {
			// Calculate region size, ensure it doesn't exceed limit
			regionSize := uintptr(memInfo.RegionSize)
			if currentAddr+regionSize > maxAddr {
				regionSize = maxAddr - currentAddr
			}

			// Read memory region
			memory := make([]byte, regionSize)
			if err = windows.ReadProcessMemory(handle, currentAddr, &memory[0], regionSize, nil); err == nil {
				select {
				case memoryChannel <- memory:
					log.Debug().Msgf("Memory region for analysis: 0x%X - 0x%X, size: %d bytes", currentAddr, currentAddr+regionSize, regionSize)
				case <-ctx.Done():
					return nil
				}
			}
		}

		// Move to next memory region
		currentAddr = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
	}

	return nil
}

// worker processes memory regions to find V4 version key
func (e *V4Extractor) worker(ctx context.Context, handle windows.Handle, memoryChannel <-chan []byte, resultChannel chan<- [2]string) {
	// Data Key scanning logic removed as per requirement.
	// Native scanner is now exclusively for Image Key (Dart mode).

	// Helper to check if byte is lowercase alphanumeric
	isAlphaNumLower := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
	}

	// Track found keys
	var imgKey string // dataKey removed
	
	// Logging flags and counters
	validatorWarned := false
	candidateCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				// Memory scanning complete, return whatever keys we found
				if candidateCount > 0 {
					msg := fmt.Sprintf("内存扫描结束，共检查了 %d 个候选图片密钥字符串", candidateCount)
					log.Debug().Msg(msg)
					if e.logger != nil {
						e.logger.LogDebug(msg)
					}
				}
				if imgKey != "" {
					select {
					case resultChannel <- [2]string{"", imgKey}:
					default:
					}
				}
				return
			}

			// Search for Image Key String (Scan for 32-byte alphanumeric string)
			// Only if we haven't found ImgKey yet
			if imgKey == "" {
				if e.validator == nil {
					if !validatorWarned {
						msg := "验证器未初始化(可能未找到*_t.dat文件)，跳过图片密钥扫描"
						log.Warn().Msg(msg)
						if e.logger != nil {
							e.logger.LogWarning(msg)
						}
						validatorWarned = true
					}
					continue
				}

				// We scan the memory block for sequences of 32 alphanumeric characters
				// The logic mimics img-key.dart: check boundaries and content
				for i := 0; i <= len(memory)-32; i++ {
					// Optimization: Check first byte
					if !isAlphaNumLower(memory[i]) {
						continue
					}

					// Boundary check: previous byte must NOT be alphanumeric (unless it's start of block)
					// Note: strictly speaking we should check across blocks, but here we check within block
					if i > 0 && isAlphaNumLower(memory[i-1]) {
						continue
					}

					// Check if we have 32 valid chars
					isValid := true
					for j := 1; j < 32; j++ {
						if !isAlphaNumLower(memory[i+j]) {
							isValid = false
							i += j // Skip forward
							break
						}
					}

					if !isValid {
						continue
					}

					// Boundary check: next byte (33rd) must NOT be alphanumeric
					if i+32 < len(memory) && isAlphaNumLower(memory[i+32]) {
						continue
					}

					// Found a candidate 32-byte string
					candidateCount++
					if candidateCount % 5000 == 0 {
						msg := fmt.Sprintf("正在扫描图片密钥... 已检查 %d 个候选字符串", candidateCount)
						log.Debug().Msg(msg)
						if e.logger != nil {
							e.logger.LogDebug(msg)
						}
					}
					
					candidate := memory[i : i+32]
					
					// Validate using existing validator (which now supports the *_t.dat check)
					// We pass the full 32 bytes, validator takes first 16
					if e.validator.ValidateImgKey(candidate) {
						// Found it!
						// Return hex encoded first 16 bytes
						foundKey := hex.EncodeToString(candidate[:16])
						if imgKey == "" {
							imgKey = foundKey
							msg := fmt.Sprintf("通过字符串扫描找到图片密钥! (在检查了 %d 个候选后) Key: %s", candidateCount, foundKey)
							log.Info().Msg(msg)
							if e.logger != nil {
								e.logger.LogStatus(1, msg)
							}
							select {
							case resultChannel <- [2]string{"", imgKey}:
							case <-ctx.Done():
								return
							}
						}
						
						// Skip past this key
						i += 32
					}
				}
			}
		}
	}
}

// validateKey validates a single key candidate and returns the key and whether it's an image key
func (e *V4Extractor) validateKey(handle windows.Handle, addr uint64) (string, bool) {
	if e.validator == nil {
		return "", false
	}

	keyData := make([]byte, 0x20) // 32-byte key
	if err := windows.ReadProcessMemory(handle, uintptr(addr), &keyData[0], uintptr(len(keyData)), nil); err != nil {
		return "", false
	}

	// Data Key validation removed.
	
	// Only check if it's a valid image key
	if e.validator.ValidateImgKey(keyData) {
		return hex.EncodeToString(keyData[:16]), true // Image key
	}

	return "", false
}