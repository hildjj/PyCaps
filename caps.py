import hashlib
import xml.etree.ElementTree as etree
import sys

def check(s):
    "Check the given string for instances of <"
    if not s:
        return s
    if s.find("<") >= 0:
        raise Exception("Being attacked by an attempt at hash collision:", s)
    return s

def get_ver_string(q):
    if q == None:
        return ''
    
    iq = etree.fromstring(q.encode('utf8'))
    print etree.tostring(iq)
    # 0. Initialize an empty string S.
    S = ''
    
    # 1. Sort the service discovery identities [14] by category and then
    # by type (if it exists) and then by xml:lang (if it exists),
    # formatted as CATEGORY '/' [TYPE] '/' [LANG] '/' [NAME]. Note that
    # each slash is included even if the TYPE, LANG, or NAME is not
    # included.
    query = iq.find("{http://jabber.org/protocol/disco#info}query")
    ids = []
    for i in query.findall('{http://jabber.org/protocol/disco#info}identity'):
        ids.append([i.get("category"),
                    i.get("type") or "",
                    i.get("{http://www.w3.org/XML/1998/namespace}lang") or "",
                    i.get("name")] or "")
    ids.sort()
    
    # 2. For each identity, append the 'category/type/lang/name' to S,
    # followed by the '<' character.
    for i in ids:
        S += "/".join([check(j) for j in i]) + "<"
    
    # 3. Sort the supported service discovery features. [15]    
    feats = []
    for f in query.findall('{http://jabber.org/protocol/disco#info}feature'):
        feats.append(f.get("var"))
    feats.sort()
    
    # 4. For each feature, append the feature to S, followed by the '<'
    # character.
    for f in feats:
        S += check(f) + "<"
    
    # 5. If the service discovery information response includes XEP-0128
    # data forms, sort the forms by the FORM_TYPE field.
    forms = {}
    for x in query.findall("{jabber:x:data}x"):
        typ = None
        form = []
        for field in x.findall("{jabber:x:data}field"):
            values = []
            for v in field.findall("{jabber:x:data}value"):
                values.append(v.text)
            name = field.get("var")
            if name == "FORM_TYPE":
                if typ:
                    print "two FORM_TYPEs"
                    sys.exit(1)
                typ = values[0]
            else:
                form.append([name, values])
        if typ:
            if typ in forms:
                print "two FORM_TYPEs the same"
                sys.exit(1)
            forms[typ] = form
    
    forms = forms.items()
    forms.sort()
    
    # 6. For each extended service discovery information form:
    for typ, fields in forms:
        # 0. Append the value of the FORM_TYPE field, followed by the '<' character.
        S += check(typ) + "<"
        
        # 1. Sort the fields by the value of the "var" attribute.
        fields.sort()
        
        # 2. For each field:
        for var, vals in fields:
            # 0. Append the value of the "var" attribute, followed by the
            # '<' character.
            S += check(var) + "<"
            
            # 1. Sort values by the XML character data of the <value/>
            # element.
            vals.sort()
            
            # 2. For each <value/> element, append the XML character data,
            # followed by the '<' character.
            for v in vals:
                S += check(v) + "<"
        
    print S
    print
    
    # 7. Compute ver by hashing S using the algorithm specified in the
    # 'hash' attribute (e.g., SHA-1 as defined in RFC 3174 [16]). The
    # hashed data MUST be generated with binary output and encoded using
    # Base64 as specified in Section 4 of RFC 4648 [17] (note: the Base64
    # output MUST NOT include whitespace and MUST set padding bits to
    # zero). [18]
    #ver = sha(S.encode('utf8')).digest().encode('base64')
    ver = hashlib.sha1(S.encode('utf8')).digest().encode('base64')
    
    return ver

###############################################################################
# Interactive
###############################################################################
if __name__ == '__main__':
    import sys, string
    data = sys.stdin.read()
    ver = get_ver_string(data)
    print ver
