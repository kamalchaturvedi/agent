package securityviolationsprocessor

import (
	"bytes"
	"fmt"
)

// parseFastBADMSG parses the BADMSG XML using a fast byte-level lexer
func parseFastBADMSG(violationDetails string) (*BADMSG, error) {
	badmsg := &BADMSG{}
	data := []byte(violationDetails)
	
	// Validate basic XML structure
	if err := validateBasicXMLStructure(data); err != nil {
		return nil, err
	}
	
	// Find all <violation> blocks
	violations := extractViolations(data)
	badmsg.RequestViolations.Violations = make([]*Violation, len(violations))
	
	for i, violData := range violations {
		badmsg.RequestViolations.Violations[i] = parseViolation(violData)
	}

	return badmsg, nil
}

// isValidProtobufString checks if a byte slice can be safely used as a protobuf string
// Protobuf strings cannot contain null bytes
func isValidProtobufString(data []byte) bool {
	return !bytes.Contains(data, []byte{0})
}

// validateBasicXMLStructure performs basic validation to detect malformed XML
func validateBasicXMLStructure(data []byte) error {
	// Track opening tags to ensure they have matching closing tags
	tagStack := make([]string, 0, 32)
	pos := 0
	n := len(data)
	
	for pos < n {
		// Find next tag
		tagStart := bytes.IndexByte(data[pos:], '<')
		if tagStart == -1 {
			break
		}
		tagStart += pos
		
		// Skip XML declaration and comments
		if tagStart+1 < n && data[tagStart+1] == '?' {
			pos = tagStart + 1
			continue
		}
		if tagStart+3 < n && data[tagStart+1] == '!' && data[tagStart+2] == '-' && data[tagStart+3] == '-' {
			pos = tagStart + 1
			continue
		}
		
		tagEnd := bytes.IndexByte(data[tagStart:], '>')
		if tagEnd == -1 {
			return fmt.Errorf("unclosed tag at position %d", tagStart)
		}
		tagEnd += tagStart
		
		// Extract tag content
		tagContent := data[tagStart+1 : tagEnd]
		
		// Skip self-closing tags and empty tags
		if len(tagContent) == 0 || tagContent[len(tagContent)-1] == '/' {
			pos = tagEnd + 1
			continue
		}
		
		// Check if it's a closing tag
		if tagContent[0] == '/' {
			// Extract closing tag name
			closingTagName := string(bytes.TrimSpace(tagContent[1:]))
			spaceIdx := bytes.IndexAny(tagContent[1:], " \t\n\r")
			if spaceIdx != -1 {
				closingTagName = string(tagContent[1 : spaceIdx+1])
			}
			
			if !isValidTagName([]byte(closingTagName)) {
				return fmt.Errorf("invalid closing tag name: %s", closingTagName)
			}
			
			// Check if it matches the most recent opening tag
			if len(tagStack) == 0 {
				return fmt.Errorf("unexpected closing tag: %s", closingTagName)
			}
			expectedTag := tagStack[len(tagStack)-1]
			if expectedTag != closingTagName {
				return fmt.Errorf("mismatched closing tag: expected </%s> but got </%s>", expectedTag, closingTagName)
			}
			tagStack = tagStack[:len(tagStack)-1]
		} else {
			// Opening tag - extract tag name
			spaceIdx := bytes.IndexAny(tagContent, " \t\n\r")
			var tagName string
			if spaceIdx == -1 {
				tagName = string(tagContent)
			} else {
				tagName = string(tagContent[:spaceIdx])
			}
			if !isValidTagName([]byte(tagName)) {
				return fmt.Errorf("invalid opening tag name: %s", tagName)
			}
			tagStack = append(tagStack, tagName)
		}
		
		pos = tagEnd + 1
	}
	
	// Check for unclosed tags
	if len(tagStack) > 0 {
		return fmt.Errorf("unclosed tags: %v", tagStack)
	}
	
	return nil
}

// isValidTagName checks if a tag name contains valid XML name characters
func isValidTagName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	// Valid XML names contain letters, digits, hyphens, underscores, and periods
	// but cannot start with digits, hyphens, or periods
	for i, b := range name {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == ':' {
			continue
		}
		if i > 0 && ((b >= '0' && b <= '9') || b == '-' || b == '.') {
			continue
		}
		return false
	}
	return true
}

// extractViolations finds all <violation>...</violation> blocks
func extractViolations(data []byte) [][]byte {
	var violations [][]byte
	pos := 0
	n := len(data)
	
	for pos < n {
		start := bytes.Index(data[pos:], []byte("<violation>"))
		if start == -1 {
			break
		}
		start += pos
		
		end := bytes.Index(data[start:], []byte("</violation>"))
		if end == -1 {
			break
		}
		end += start + len("</violation>")
		
		contentStart := start + len("<violation>")
		contentEnd := end - len("</violation>")
		violations = append(violations, data[contentStart:contentEnd])
		
		pos = end
	}
	
	return violations
}

// findElement finds the content of an XML element
func findElement(data []byte, tagName string) []byte {
	startTag := []byte("<" + tagName + ">")
	endTag := []byte("</" + tagName + ">")
	
	start := bytes.Index(data, startTag)
	if start == -1 {
		return nil
	}
	start += len(startTag)
	
	end := bytes.Index(data[start:], endTag)
	if end == -1 {
		return nil
	}
	
	return data[start : start+end]
}

// parseViolation parses a single violation block
func parseViolation(data []byte) *Violation {
	v := &Violation{}
	
	// Extract simple text fields
	if content := findElement(data, "viol_name"); content != nil {
		v.ViolName = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "context"); content != nil {
		v.Context = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "uri"); content != nil {
		v.Uri = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "buffer"); content != nil {
		v.Buffer = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "specific_desc"); content != nil {
		v.SpecificDesc = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "param_name"); content != nil {
		v.ParamName = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "header_name"); content != nil {
		v.HeaderName = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "cookie_name"); content != nil {
		v.CookieName = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "header_len"); content != nil {
		v.HeaderLength = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "header_len_limit"); content != nil {
		v.HeaderLengthLimit = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "cookie_len"); content != nil {
		v.CookieLength = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "cookie_len_limit"); content != nil {
		v.CookieLengthLimit = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "uri_len"); content != nil {
		v.UriLength = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "uri_len_limit"); content != nil {
		v.UriLengthLimit = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "defined_length"); content != nil {
		v.DefinedLength = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "detected_length"); content != nil {
		v.DetectedLength = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "total_len"); content != nil {
		v.TotalLen = string(bytes.TrimSpace(content))
	}
	if content := findElement(data, "total_len_limit"); content != nil {
		v.TotalLenLimit = string(bytes.TrimSpace(content))
	}
	
	// Parse nested structures
	if pdData := findElement(data, "parameter_data"); pdData != nil {
		v.ParameterData = parseParameterData(pdData)
	}
	
	if pdData := findElement(data, "param_data"); pdData != nil {
		v.ParamData = parseParamData(pdData)
	}
	
	// Check for context_data wrapper
	if ctxWrap := findElement(data, "context_data"); ctxWrap != nil {
		if pdData := findElement(ctxWrap, "param_data"); pdData != nil {
			v.ContextDataWrap = &ContextDataWrapper{
				ParamData: parseParamData(pdData),
			}
		}
	}
	
	if headerData := findElement(data, "header"); headerData != nil {
		v.Header = parseHeader(headerData)
	}
	
	if headerData := findElement(data, "header_data"); headerData != nil {
		v.HeaderData = parseHeader(headerData)
	}
	
	if cookieData := findElement(data, "cookie"); cookieData != nil {
		v.Cookie = parseCookie(cookieData)
	}
	
	if objData := findElement(data, "object_data"); objData != nil {
		if obj := findElement(objData, "object"); obj != nil {
			v.UriObjectData = &UriObjectData{
				Object: string(bytes.TrimSpace(obj)),
			}
		}
	}
	
	// Parse signature data (can have multiple)
	v.SigData = parseSigDataList(data)
	
	return v
}

// parseParameterData parses parameter_data nested element
func parseParameterData(data []byte) *ParameterData {
	pd := &ParameterData{}
	
	// Keep name and value as-is (base64) - they will be decoded later by violations_parser
	if name := findElement(data, "name"); name != nil {
		pd.Name = string(bytes.TrimSpace(name))
	}
	
	if value := findElement(data, "value"); value != nil {
		pd.Value = string(bytes.TrimSpace(value))
	}
	
	if isDecoded := findElement(data, "is_base64_decoded"); isDecoded != nil {
		pd.IsBase64Decoded = string(bytes.TrimSpace(isDecoded)) == "true"
	}
	
	return pd
}

// parseParamData parses param_data nested element
func parseParamData(data []byte) *ParamData {
	pd := &ParamData{}
	
	// Keep name and value as-is (base64) - they will be decoded later by violations_parser
	if name := findElement(data, "name"); name != nil {
		pd.Name = string(bytes.TrimSpace(name))
	}
	
	if value := findElement(data, "value"); value != nil {
		pd.Value = string(bytes.TrimSpace(value))
	}
	
	if isDecoded := findElement(data, "is_base64_decoded"); isDecoded != nil {
		pd.IsBase64Decoded = string(bytes.TrimSpace(isDecoded)) == "true"
	}
	
	return pd
}

// parseHeader parses header nested element
func parseHeader(data []byte) *Header {
	h := &Header{}
	
	// Check for nested elements first
	if name := findElement(data, "header_name"); name != nil {
		h.Name = string(bytes.TrimSpace(name))
	}
	
	if value := findElement(data, "header_value"); value != nil {
		h.Value = string(bytes.TrimSpace(value))
	}
	
	if actual := findElement(data, "header_actual_value"); actual != nil {
		h.ActualValue = string(bytes.TrimSpace(actual))
	}
	
	if matched := findElement(data, "header_matched_value"); matched != nil {
		h.MatchedValue = string(bytes.TrimSpace(matched))
	}
	
	if isDecoded := findElement(data, "is_base64_decoded"); isDecoded != nil {
		h.IsBase64Decoded = string(bytes.TrimSpace(isDecoded)) == "true"
	}
	
	// If no nested elements found, treat entire content as Text (base64 encoded)
	if h.Name == "" && h.Value == "" && h.ActualValue == "" && h.MatchedValue == "" {
		text := bytes.TrimSpace(data)
		if len(text) > 0 && !bytes.Contains(text, []byte("<")) {
			h.Text = string(text)
		}
	}
	
	return h
}

// parseCookie parses cookie nested element
func parseCookie(data []byte) *Cookie {
	c := &Cookie{}
	
	// Check for nested elements first
	if name := findElement(data, "cookie_name"); name != nil {
		c.Name = string(bytes.TrimSpace(name))
	}
	
	if value := findElement(data, "cookie_value"); value != nil {
		c.Value = string(bytes.TrimSpace(value))
	}
	
	if isDecoded := findElement(data, "is_base64_decoded"); isDecoded != nil {
		c.IsBase64Decoded = string(bytes.TrimSpace(isDecoded)) == "true"
	}
	
	// If no nested elements found, treat entire content as Text (base64 encoded)
	if c.Name == "" && c.Value == "" {
		text := bytes.TrimSpace(data)
		if len(text) > 0 && !bytes.Contains(text, []byte("<")) {
			c.Text = string(text)
		}
	}
	
	return c
}

// parseSigDataList parses all sig_data elements
func parseSigDataList(data []byte) []*SigData {
	var sigList []*SigData
	pos := 0
	n := len(data)
	
	for pos < n {
		start := bytes.Index(data[pos:], []byte("<sig_data>"))
		if start == -1 {
			break
		}
		start += pos
		
		end := bytes.Index(data[start:], []byte("</sig_data>"))
		if end == -1 {
			break
		}
		end += start + len("</sig_data>")
		
		contentStart := start + len("<sig_data>")
		contentEnd := end - len("</sig_data>")
		sigData := parseSigData(data[contentStart:contentEnd])
		sigList = append(sigList, sigData)
		
		pos = end
	}
	
	return sigList
}

// parseSigData parses a single sig_data element
func parseSigData(data []byte) *SigData {
	sd := &SigData{}
	
	if sigID := findElement(data, "sig_id"); sigID != nil {
		sd.SigID = string(bytes.TrimSpace(sigID))
	}
	
	if blockMask := findElement(data, "blocking_mask"); blockMask != nil {
		sd.BlockingMask = string(bytes.TrimSpace(blockMask))
	}
	
	if kwData := findElement(data, "kw_data"); kwData != nil {
		if buffer := findElement(kwData, "buffer"); buffer != nil {
			sd.KwData.Buffer = string(bytes.TrimSpace(buffer))
		}
		if offset := findElement(kwData, "offset"); offset != nil {
			sd.KwData.Offset = string(bytes.TrimSpace(offset))
		}
		if length := findElement(kwData, "length"); length != nil {
			sd.KwData.Length = string(bytes.TrimSpace(length))
		}
	}
	
	return sd
}
