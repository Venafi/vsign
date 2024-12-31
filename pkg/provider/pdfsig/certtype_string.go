package pdfsig

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[CertificationSignature-1]
	_ = x[ApprovalSignature-2]
	_ = x[UsageRightsSignature-3]
	_ = x[TimeStampSignature-4]
}

const _CertType_name = "CertificationSignatureApprovalSignatureUsageRightsSignatureTimeStampSignature"

var _CertType_index = [...]uint8{0, 22, 39, 59, 77}

func (i CertType) String() string {
	i -= 1
	if i >= CertType(len(_CertType_index)-1) {
		return "CertType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _CertType_name[_CertType_index[i]:_CertType_index[i+1]]
}
