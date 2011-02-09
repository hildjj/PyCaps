q = u"""<iq from='walto@sz.webex.com/wbxconnect' id='conid18' to='tonys@sz.webex.com/wbxconnect' type='result' xml:lang='en'><query node='http://webex.com/connect#mCqIvMWPVtmlG1H9Ij6RvosKH2E=' xmlns='http://jabber.org/protocol/disco#info'><identity category='client' name='Cisco WebEx Connect 6.7.0' type='im'/><feature var='http://jabber.org/protocol/bytestreams'/><feature var='http://jabber.org/protocol/caps'/><feature var='http://jabber.org/protocol/commands'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='http://jabber.org/protocol/muc'/><feature var='http://jabber.org/protocol/si'/><feature var='http://jabber.org/protocol/si/profile/file-transfer'/><feature var='http://jabber.org/protocol/xhtml-im'/><feature var='http://webex.com/connect/aes-file-transfer'/><feature var='http://webex.com/connect/customcaps/av'/><feature var='http://webex.com/connect/customcaps/av-ex'/><feature var='http://webex.com/connect/customcaps/connectclient'/><feature var='http://webex.com/connect/customcaps/ds'/><feature var='http://webex.com/connect/customcaps/jinglecmd'/><feature var='http://webex.com/connect/customcaps/meeting'/><feature var='http://webex.com/connect/customcaps/msgcmd'/><feature var='http://webex.com/connect/customcaps/picture-share'/><feature var='http://webex.com/connect/customcaps/ssl-gw'/><feature var='jabber:iq:version'/><feature var='jabber:x:conference'/></query></iq>"""


from sha import sha
import xml.etree.ElementTree as etree
import sys

def check(s):
    "Check the given string for instances of <"
    if not s:
        return s
    if s.find("<") >= 0:
        raise Exception("Being attacked by an attempt at hash collision:", s)
    return s

iq = etree.fromstring(q.encode('utf8'))

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
ver = sha(S.encode('utf8')).digest().encode('base64')

node = query.get('node')
node = node.split('#')[0]

print """
<presence from='%s'>
  <c xmlns='http://jabber.org/protocol/caps' 
     hash='sha-1'
     node='%s'
     ver='%s'/>
</presence>""" % (iq.get('from'), node, ver.rstrip())
