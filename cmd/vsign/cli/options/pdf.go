//
// Copyright 2023 Venafi.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import (
	"github.com/spf13/cobra"
)

// SignOptions is the top level wrapper for the sign command.
type PDFOptions struct {
	Name     string
	Location string
	Reason   string
	Contact  string
	TSA      string
	Visual   bool
}

var _ Interface = (*PDFOptions)(nil)

// AddFlags implements Interface
func (o *PDFOptions) AddFlags(cmd *cobra.Command) {

	cmd.Flags().StringVar(&o.Name, "name", "Acme Signer", "Name of the signatory")
	cmd.Flags().StringVar(&o.Location, "location", "Palo Alto", "Location of the signatory")
	cmd.Flags().StringVar(&o.Reason, "reason", "Contract", "Reason for signing")
	cmd.Flags().StringVar(&o.Contact, "contact", "acme@example.com", "Contact information for the signatory")
	cmd.Flags().StringVar(&o.TSA, "tsa", "http://timestamp.digicert.com", "URL for Time-Stamp Authority (default: http://timestamp.digicert.com)")
	cmd.Flags().BoolVar(&o.Visual, "visual", false, "add visual signature to pdf")

}
