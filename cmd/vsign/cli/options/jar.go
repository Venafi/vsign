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
type JarOptions struct {
	SectionsOnly    bool
	InlineSignature bool
	APKV2Present    bool
}

var _ Interface = (*JarOptions)(nil)

// AddFlags implements Interface
func (o *JarOptions) AddFlags(cmd *cobra.Command) {

	cmd.Flags().BoolVar(&o.SectionsOnly, "sections-only", false, "(JAR) Don't compute hash of entire manifest")
	cmd.Flags().BoolVar(&o.InlineSignature, "inline-signature", false, "(JAR) Include .SF inside the signature block")
	cmd.Flags().BoolVar(&o.APKV2Present, "apk-v2-present", false, "(JAR) Add X-Android-APK-Signed header to signature")

}
