// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

// XML struct definitions for parsing violation_details

// ParameterData represents parameter data in violation XML
type ParameterData struct {
	Name            string `xml:"name"`
	Value           string `xml:"value"`
	IsBase64Decoded bool   `xml:"is_base64_decoded"`
}

// ParamData represents alternate parameter data format in violation XML
type ParamData struct {
	Name            string `xml:"name"`
	Value           string `xml:"value"`
	IsBase64Decoded bool   `xml:"is_base64_decoded"`
}

// ContextDataWrapper wraps context-specific data in XML
type ContextDataWrapper struct {
	ParamData *ParamData `xml:"param_data"`
}

// Header represents HTTP header data in violation XML
type Header struct {
	Text            string `xml:",chardata"`
	Name            string `xml:"header_name"`
	Value           string `xml:"header_value"`
	ActualValue     string `xml:"header_actual_value"`
	MatchedValue    string `xml:"header_matched_value"`
	IsBase64Decoded bool   `xml:"is_base64_decoded"`
}

// Cookie represents cookie data in violation XML
type Cookie struct {
	Text            string `xml:",chardata"`
	Name            string `xml:"cookie_name"`
	Value           string `xml:"cookie_value"`
	IsBase64Decoded bool   `xml:"is_base64_decoded"`
}

// UriObjectData represents URI object data in violation XML
type UriObjectData struct {
	Object string `xml:"object"`
}

// SigData represents signature data in violation XML
//
//nolint:revive // nested struct for XML unmarshaling
type SigData struct {
	SigID        string `xml:"sig_id"`
	BlockingMask string `xml:"blocking_mask"`
	KwData       struct {
		Buffer string `xml:"buffer"`
		Offset string `xml:"offset"`
		Length string `xml:"length"`
	} `xml:"kw_data"`
}

// Violation represents an individual violation in the XML structure
// Only includes fields actually used in processing to reduce memory allocations
//
//nolint:govet // fieldalignment: XML struct field order matters for unmarshaling
type Violation struct {
	ViolName          string              `xml:"viol_name"`
	Context           string              `xml:"context"`
	ContextDataWrap   *ContextDataWrapper `xml:"context_data"`
	ParameterData     *ParameterData      `xml:"parameter_data"`
	ParamData         *ParamData          `xml:"param_data"`
	ParamName         string              `xml:"param_name"`
	IsBase64Decoded   bool                `xml:"is_base64_decoded"`
	Header            *Header             `xml:"header"`
	HeaderData        *Header             `xml:"header_data"`
	HeaderName        string              `xml:"header_name"`
	HeaderLength      string              `xml:"header_len"`
	HeaderLengthLimit string              `xml:"header_len_limit"`
	Cookie            *Cookie             `xml:"cookie"`
	CookieName        string              `xml:"cookie_name"`
	CookieLength      string              `xml:"cookie_len"`
	CookieLengthLimit string              `xml:"cookie_len_limit"`
	Buffer            string              `xml:"buffer"`
	SpecificDesc      string              `xml:"specific_desc"`
	Uri               string              `xml:"uri"`
	UriObjectData     *UriObjectData      `xml:"object_data"`
	UriLength         string              `xml:"uri_len"`
	UriLengthLimit    string              `xml:"uri_len_limit"`
	DefinedLength     string              `xml:"defined_length"`
	DetectedLength    string              `xml:"detected_length"`
	TotalLen          string              `xml:"total_len"`
	TotalLenLimit     string              `xml:"total_len_limit"`
	SigData           []*SigData          `xml:"sig_data"`
}

// BADMSG represents the root structure of NGINX App Protect violation XML
// Only includes fields actually used in processing to reduce memory allocations
//
//nolint:revive // nested structs for byte-level parsing
type BADMSG struct {
	RequestViolations struct {
		Violations []*Violation
	}
}
