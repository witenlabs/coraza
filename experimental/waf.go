// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Modified by Witen Labs in 2026: document audit writer retirement.

package experimental

import (
	"io"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type Options = corazawaf.Options

// WAFWithOptions is an interface that allows to create transactions
// with options
type WAFWithOptions interface {
	NewTransactionWithOptions(Options) types.Transaction
}

// WAFWithRules is an interface that allows to inspect the number of
// rules loaded in a WAF instance. This is useful for connectors that
// need to verify rule loading or implement configuration caching.
type WAFWithRules interface {
	// RulesCount returns the number of rules in this WAF.
	RulesCount() int
}

// WAFCloser retires a WAF's cached resources and audit writer. Stop creating new
// transactions before calling Close. In-flight transactions keep their audit
// writer until the last transaction Close, which returns any deferred close error.
// This will be promoted to the public WAF interface in v4.
type WAFCloser interface {
	io.Closer
}
