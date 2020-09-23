package cabf_br

/*
 * ZLint Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/************************************************
BRs: 7.1.2.2b cRLDistributionPoints
This extension MUST be present and MUST NOT be marked critical.
It MUST contain the HTTP URL of the CA’s CRL service.
************************************************/

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
	"github.com/zmap/zlint/v2/util"
)

type subCACRLDistNoUrl struct{}

func (l *subCACRLDistNoUrl) Initialize() error {
	return nil
}

func (l *subCACRLDistNoUrl) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && util.IsExtInCert(c, util.CrlDistOID) && util.IsServerAuthCert(c)
}

func (l *subCACRLDistNoUrl) Execute(c *x509.Certificate) *lint.LintResult {
	for _, s := range c.CRLDistributionPoints {
		if strings.HasPrefix(s, "http://") {
			return &lint.LintResult{Status: lint.Pass}
		}
	}
	return &lint.LintResult{Status: lint.Error}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_ca_crl_distribution_points_does_not_contain_url",
		Description:   "Subordinate CA Certificate: cRLDistributionPoints MUST contain the HTTP URL of the CA's CRL service.",
		Citation:      "BRs: 7.1.2.2",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &subCACRLDistNoUrl{},
	})
}
