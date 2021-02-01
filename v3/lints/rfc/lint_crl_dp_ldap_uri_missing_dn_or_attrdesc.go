/*
 * ZLint Copyright 2021 Regents of the University of Michigan
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

package rfc

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2/lint"
)

type crlDpLdapURIMissingDnOrAttrdesc struct{}

func (l *crlDpLdapURIMissingDnOrAttrdesc) Initialize() error {
	return nil
}

func (l *crlDpLdapURIMissingDnOrAttrdesc) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.CrlDistOID)
}

func (l *crlDpLdapURIMissingDnOrAttrdesc) Execute(c *x509.Certificate) *lint.LintResult {
	dp := util.GetExtFromCert(c, util.CrlDistOID)
	var cdp []distributionPoint
	_, err := asn1.Unmarshal(dp.Value, &cdp)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	for _, dp := range cdp {
		fmt.Printf("%v\n", dp.DistributionPoint.FullName)
	}
	return &lint.LintResult{Status: lint.Pass}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_crl_dp_ldap_uri_missing_dn_or_attrdesc",
		Description:   "Fill this in...",
		Citation:      "Fill this in...",
		Source:        lint.RFC5280,
		EffectiveDate: util.RFC3280Date,
		Lint:          &crlDpLdapURIMissingDnOrAttrdesc{},
	})
}
