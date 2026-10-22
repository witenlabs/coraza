// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Modified by Witen Labs in 2026: cover audit ownership and draining close errors.

package coraza

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type lifecycleAuditWriter struct {
	closes atomic.Int64
	writes atomic.Int64
	err    error
}

func (*lifecycleAuditWriter) Init(plugintypes.AuditLogConfig) error { return nil }
func (w *lifecycleAuditWriter) Write(plugintypes.AuditLog) error {
	if w.closes.Load() != 0 {
		return errors.New("write after audit writer closed")
	}
	w.writes.Add(1)
	return nil
}
func (w *lifecycleAuditWriter) Close() error {
	w.closes.Add(1)
	return w.err
}

// Not a profile: this asserts ownership across WAF/transaction Close and failed construction.
func TestAuditWriterLifecycle(t *testing.T) {
	for _, pending := range []int{0, 8} {
		for _, closeFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("pending=%d/error=%t", pending, closeFails), func(t *testing.T) {
				writer := &lifecycleAuditWriter{}
				if closeFails {
					writer.err = errors.New("audit close failed")
				}
				config := NewWAFConfig().(*wafConfig)
				config.auditLog = &auditLogConfig{writer: writer}
				waf, err := NewWAF(config)
				if err != nil {
					t.Fatal(err)
				}
				txs := make([]types.Transaction, pending)
				for i := range txs {
					txs[i] = waf.NewTransaction()
				}
				closer := waf.(interface{ Close() error })
				err = closer.Close()
				if pending == 0 {
					if !errors.Is(err, writer.err) || writer.closes.Load() != 1 {
						t.Fatalf("immediate close: err=%v closes=%d", err, writer.closes.Load())
					}
				} else {
					if err != nil || writer.closes.Load() != 0 {
						t.Fatalf("closed before transactions drained: %v", err)
					}
					var wg sync.WaitGroup
					var closeErrors atomic.Int64
					for _, tx := range txs {
						wg.Go(func() {
							tx.ProcessLogging()
							if err := tx.Close(); err != nil {
								if !errors.Is(err, writer.err) {
									t.Error(err)
								}
								closeErrors.Add(1)
							}
						})
					}
					wg.Wait()
					wantErrors := int64(0)
					if closeFails {
						wantErrors = 1
					}
					if writer.writes.Load() != int64(pending) || writer.closes.Load() != 1 || closeErrors.Load() != wantErrors {
						t.Fatalf("drain writes=%d closes=%d errors=%d", writer.writes.Load(), writer.closes.Load(), closeErrors.Load())
					}
				}
				if err := closer.Close(); !errors.Is(err, writer.err) || writer.closes.Load() != 1 {
					t.Fatalf("repeated close: err=%v closes=%d", err, writer.closes.Load())
				}
			})
		}
	}
	t.Run("failed validation", func(t *testing.T) {
		writer := &lifecycleAuditWriter{}
		config := NewWAFConfig().WithRequestBodyLimit(0).(*wafConfig)
		config.auditLog = &auditLogConfig{writer: writer}
		if waf, err := NewWAF(config); err == nil || waf != nil {
			t.Fatalf("invalid config accepted: %v %v", waf, err)
		}
		if writer.closes.Load() != 1 {
			t.Fatalf("failed constructor retained audit writer: closes=%d", writer.closes.Load())
		}
	})
}

// wafWithRules mirrors experimental.WAFWithRules for testing without import cycle.
type wafWithRules interface {
	RulesCount() int
}

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GiB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GiB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

type testAuditLogWriter struct {
	plugintypes.AuditLogWriter
}

func (*testAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	return nil
}

func TestPopulateAuditLog(t *testing.T) {
	writer := &testAuditLogWriter{}

	testCases := map[string]struct {
		config *wafConfig
		check  func(*testing.T, *corazawaf.WAF)
	}{
		"empty config": {
			config: &wafConfig{},
			check:  func(*testing.T, *corazawaf.WAF) {},
		},
		"with relevant only": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					relevantOnly: true,
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if waf.AuditEngine != types.AuditEngineRelevantOnly {
					t.Fatal("expected AuditLogRelevantOnly to be true")
				}
			},
		},
		"with parts": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					parts: []types.AuditLogPart{
						types.AuditLogPartRequestHeaders,
						types.AuditLogPartResponseBody,
					},
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if want, have := []types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}, waf.AuditLogParts; len(want) != len(have) {
					t.Fatalf("unexpected AuditLogParts: want %v, have %v", want, have)
				}
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if reflect.DeepEqual(waf.AuditLogWriter(), &writer) {
					t.Fatal("expected AuditLogWriter to be set")
				}
			},
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := &corazawaf.WAF{}
			populateAuditLog(waf, tCase.config)
			tCase.check(t, waf)
		})
	}
}

func TestDetectionOnlyEnforcesProcessPartialBodyLimitActions(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine DetectionOnly
		SecRequestBodyAccess On
		SecRequestBodyLimitAction Reject
		SecResponseBodyAccess On
		SecResponseBodyLimitAction Reject
	`))
	if err != nil {
		t.Fatal(err)
	}

	w := waf.(wafWrapper).waf
	if w.RequestBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected RequestBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.RequestBodyLimitAction)
	}
	if w.ResponseBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected ResponseBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.ResponseBodyLimitAction)
	}
}

func TestRulesCount(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	rules, ok := waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 0 {
		t.Fatalf("expected 0 rules, got %d", rules.RulesCount())
	}

	waf, err = NewWAF(NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`).
		WithDirectives(`SecRule REQUEST_URI "/test" "id:2,phase:1,deny,status:403"`))
	if err != nil {
		t.Fatal(err)
	}

	rules, ok = waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 2 {
		t.Fatalf("expected 2 rules, got %d", rules.RulesCount())
	}
}
