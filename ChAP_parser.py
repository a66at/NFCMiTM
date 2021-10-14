# ChAP things from Peter Fillmore

# known AIDs
# please mail new AIDs to aid@rfidiot.org
KNOWN_AIDS = [
    ['VISA', 0xa0, 0x00, 0x00, 0x00, 0x03],
    ['VISA Debit/Credit', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
    ['VISA Credit', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x01],
    ['VISA Debit', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x02],
    ['VISA Electron', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10],
    ['VISA Interlink', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x30, 0x10],
    ['VISA Plus', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10],
    ['VISA ATM', 0xa0, 0x00, 0x00, 0x00, 0x03, 0x99, 0x99, 0x10],
    ['MASTERCARD', 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],
    ['Maestro', 0xa0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60],
    ['Maestro UK', 0xa0, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01],
    ['Maestro TEST', 0xb0, 0x12, 0x34, 0x56, 0x78],
    ['Self Service', 0xa0, 0x00, 0x00, 0x00, 0x24, 0x01],
    ['American Express', 0xa0, 0x00, 0x00, 0x00, 0x25],
    ['ExpressPay', 0xa0, 0x00, 0x00, 0x00, 0x25, 0x01, 0x07, 0x01],
    ['Link', 0xa0, 0x00, 0x00, 0x00, 0x29, 0x10, 0x10],
    ['Alias AID', 0xa0, 0x00, 0x00, 0x00, 0x29, 0x10, 0x10],
]

# Master Data File for PSE
DF_PSE = [0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31]

# define the apdus used in this script
AAC = 0
TC = 0x40
ARQC = 0x80
GENERATE_AC = [0x80, 0xae]
INTERNAL_AUTHENTICATE = [0x00, 0x88]
GET_CHALLENGE = [0x00, 0x84, 0x00, 0x00]
GET_DATA = [0x80, 0xca]
GET_PROCESSING_OPTIONS = [0x80, 0xa8, 0x00, 0x00]
GET_RESPONSE = [0x00, 0xC0, 0x00, 0x00]
READ_RECORD = [0x00, 0xb2]
SELECT = [0x00, 0xA4, 0x04, 0x00]
UNBLOCK_PIN = [0x84, 0x24, 0x00, 0x00, 0x00]
VERIFY = [0x00, 0x20, 0x00, 0x80]
COMPUTE_CRYPTOGRAPHIC_CHECKSUM = [0x80, 0x2A, 0x8E, 0x80];
# BRUTE_AID= [0xa0,0x00,0x00,0x00]
BRUTE_AID = []

# define tags for response
BINARY = 0
TEXT = 1
BER_TLV = 2
NUMERIC = 3
MIXED = 4
TEMPLATE = 0
ITEM = 1
VALUE = 2
SFI = 0x88
CDOL1 = 0x8c
CDOL2 = 0x8d
TAGS = {
    0x4f: ['Application Identifier (AID)', BINARY, ITEM],
    0x50: ['Application Label', TEXT, ITEM],
    0x56: ['Track 1 Data', TEXT, ITEM],
    0x57: ['Track 2 Equivalent Data', BINARY, ITEM],
    0x5a: ['Application Primary Account Number (PAN)', BINARY, ITEM],
    0x61: ['Application Template', BINARY, TEMPLATE],
    0x6f: ['File Control Information (FCI) Template', BINARY, TEMPLATE],
    0x70: ['Record Template', BINARY, TEMPLATE],
    0x77: ['Response Message Template Format 2', BINARY, TEMPLATE],
    0x80: ['Response Message Template Format 1', BINARY, ITEM],
    0x82: ['Application Interchange Profile', BINARY, ITEM],
    0x83: ['Command Template', BER_TLV, ITEM],
    0x84: ['DF Name', MIXED, ITEM],
    0x86: ['Issuer Script Command', BER_TLV, ITEM],
    0x87: ['Application Priority Indicator', BINARY, ITEM],
    0x88: ['Short File Identifier', BINARY, ITEM],
    0x8a: ['Authorisation Response Code', BINARY, VALUE],
    0x8c: ['Card Risk Management Data Object List 1 (CDOL1)', BINARY, ITEM],
    0x8d: ['Card Risk Management Data Object List 2 (CDOL2)', BINARY, ITEM],
    0x8e: ['Cardholder Verification Method (CVM) List', BINARY, ITEM],
    0x8f: ['Certification Authority Public Key Index', BINARY, ITEM],
    0x90: ['Issuer Public Key Certificate', BINARY, ITEM],
    0x93: ['Signed Static Application Data', BINARY, ITEM],
    0x94: ['Application File Locator', BINARY, ITEM],
    0x95: ['Terminal Verification Results', BINARY, VALUE],
    0x97: ['Transaction Certificate Data Object List (TDOL)', BER_TLV, ITEM],
    0x9c: ['Transaction Type', BINARY, VALUE],
    0x9d: ['Directory Definition File', BINARY, ITEM],
    0xa5: ['Proprietary Information', BINARY, TEMPLATE],
    0x5f20: ['Cardholder Name', TEXT, ITEM],
    0x5f24: ['Application Expiration Date YYMMDD', NUMERIC, ITEM],
    0x5f25: ['Application Effective Date YYMMDD', NUMERIC, ITEM],
    0x5f28: ['Issuer Country Code', NUMERIC, ITEM],
    0x5f2a: ['Transaction Currency Code', BINARY, VALUE],
    0x5f2d: ['Language Preference', TEXT, ITEM],
    0x5f30: ['Service Code', NUMERIC, ITEM],
    0x5f34: ['Application Primary Account Number (PAN) Sequence Number', NUMERIC, ITEM],
    0x5f50: ['Issuer URL', TEXT, ITEM],
    0x92: ['Issuer Public Key Remainder', BINARY, ITEM],
    0x9a: ['Transaction Date', BINARY, VALUE],
    0x9f02: ['Amount, Authorised (Numeric)', BINARY, ITEM],
    0x9f03: ['Amount, Other (Numeric)', BINARY, ITEM],
    0x9f04: ['Amount, Other (Binary)', BINARY, ITEM],
    0x9f05: ['Application Discretionary Data', BINARY, ITEM],
    0x9f07: ['Application Usage Control', BINARY, ITEM],
    0x9f08: ['Application Version Number', BINARY, ITEM],
    0x9f0d: ['Issuer Action Code - Default', BINARY, ITEM],
    0x9f0e: ['Issuer Action Code - Denial', BINARY, ITEM],
    0x9f0f: ['Issuer Action Code - Online', BINARY, ITEM],
    0x9f10: ['Issuer Application Data', BINARY, ITEM],
    0x9f11: ['Issuer Code Table Index', BINARY, ITEM],
    0x9f12: ['Application Preferred Name', TEXT, ITEM],
    0x9f1a: ['Terminal Country Code', BINARY, VALUE],
    0x9f1f: ['Track 1 Discretionary Data', TEXT, ITEM],
    0x9f20: ['Track 2 Discretionary Data', TEXT, ITEM],
    0x9f21: ['Transaction Time', BINARY, ITEM],
    0x9f26: ['Application Cryptogram', BINARY, ITEM],
    0x9f27: ['Cryptogram Information Data', BINARY, ITEM],
    0x9f32: ['Issuer Public Key Exponent', BINARY, ITEM],
    0x9f36: ['Application Transaction Counter', BINARY, ITEM],
    0x9f37: ['Unpredictable Number', BINARY, VALUE],
    0x9f38: ['Processing Options Data Object List (PDOL)', BINARY, TEMPLATE],
    0x9f42: ['Application Currency Code', NUMERIC, ITEM],
    0x9f44: ['Application Currency Exponent', NUMERIC, ITEM],
    0x9f46: ['ICC Public Key Certificate', BINARY, ITEM],
    0x9f47: ['ICC Public Key Exponent', BINARY, ITEM],
    0x9f4a: ['Static Data Authentication Tag List', BINARY, ITEM],
    0x9f4b: ['Signed Dynamic Application Data', BINARY, ITEM],
    0x9f4d: ['Log Entry', BINARY, ITEM],
    0x9f60: ['CVC3 Track 1', BINARY, ITEM],
    0x9f61: ['CVC3 Track 2', BINARY, ITEM],
    0x9f62: ['Track 1 Bit Map for CVC3 (PCVC3TRACK1)', BINARY, ITEM],
    0x9f63: ['Track 1 Bit Map for UN and ATC (PUNATCTRACK1)', BINARY, ITEM],
    0x9f64: ['Track 1 Nr of ATC Digits (NATCTRACK1)', BINARY, ITEM],
    0x9f65: ['Track 2 Bit Map for CVC3 (PCVC3TRACK2)', BINARY, ITEM],
    0x9f66: ['Track 2 Bit Map for UN and ATC (PUNATCTRACK2)', BINARY, ITEM],
    0x9f67: ['Track 2 Number of ATC Digits (NATCTRACK2)', BINARY, ITEM],
    0x9f6b: ['Track 2 Data', BINARY, ITEM],
    0x9f6c: ['Application Version Number (Card)', BINARY, ITEM],

    # 0x9f66:['Card Production Life Cycle',BINARY,ITEM],
    0xbf0c: ['File Control Information (FCI) Issuer Discretionary Data', BINARY, TEMPLATE],
}

# // conflicting item - need to check
# // 0x9f38:['Processing Optional Data Object List',BINARY,ITEM],

# define BER-TLV masks

TLV_CLASS_MASK = {
    0x00: 'Universal class',
    0x40: 'Application class',
    0x80: 'Context-specific class',
    0xc0: 'Private class',
}

# if TLV_TAG_NUMBER_MASK bits are set, refer to next byte(s) for tag number
# otherwise it's b1-5
TLV_TAG_NUMBER_MASK = 0x1f

# if TLV_DATA_MASK bit is set it's a 'Constructed data object'
# otherwise, 'Primitive data object'
TLV_DATA_MASK = 0x20
TLV_DATA_TYPE = ['Primitive data object', 'Constructed data object']

# if TLV_TAG_MASK is set another tag byte follows
TLV_TAG_MASK = 0x80
TLV_LENGTH_MASK = 0x80

# define AIP mask
AIP_MASK = {
    0x01: 'CDA Supported (Combined Dynamic Data Authentication / Application Cryptogram Generation)',
    0x02: 'RFU',
    0x04: 'Issuer authentication is supported',
    0x08: 'Terminal risk management is to be performed',
    0x10: 'Cardholder verification is supported',
    0x20: 'DDA supported (Dynamic Data Authentication)',
    0x40: 'SDA supported (Static Data Authentiction)',
    0x80: 'RFU'
}

# define dummy transaction values (see TAGS for tag names)
# for generate_ac
TRANS_VAL = {
    0x9f02: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],  # Amount, Authorised (Numeric)
    0x9f03: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # Amount, Other (Numeric)
    0x9f1a: [0x00, 0x36],  # Terminal Country Code (australia
    0x95: [0x00, 0x00, 0x00, 0x00, 0x00],  # Terminal Verification Results
    0x5f2a: [0x00, 0x36],  # Transaction Currency Code (australia
    0x9a: [0x14, 0x01, 0x01],  # Transaction Date
    0x9c: [0x00],  # Transaction Type (goods and service)
    0x9f37: [0x00, 0x00, 0x00, 0x00],  # Unpredictable Number
    0x9f35: [0x11],  # terminal type (online only, attended)
    0x9f45: [0x00, 0x00],  # Data Authentication Code
    # 0x9f4c:[0x00,0x00,0x00,0x00,0x00], #ICC Dynamic Number
    0x9f34: [0x00, 0x00, 0x00],  # Cardholder Verification Method (CVM) Results unknown
    0x9f4c: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 0x9f66:[0xD7,0x20,0xC0,0x00],
    0x91: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # Issuer Authentication Data
    0x8a: [0x00, 0x00],  # Authorisation Response Code
    0x9f21: [0x01, 0x01, 0x01],  # transaction time
    0x9f7c: [0x00] * 0x14,
}

# define SW1 return values
SW1_RESPONSE_BYTES = 0x61
SW1_WRONG_LENGTH = 0x6c
SW12_OK = [0x90, 0x00]
SW12_NOT_SUPORTED = [0x6a, 0x81]
SW12_NOT_FOUND = [0x6a, 0x82]
SW12_COND_NOT_SAT = [0x69, 0x85]  # conditions of use not satisfied
PIN_BLOCKED = [0x69, 0x83]
PIN_BLOCKED2 = [0x69, 0x84]
PIN_WRONG = 0x63

# some human readable error messages
ERRORS = {
    '6700': "Not known",
    '6985': "Conditions of use not satisfied or Command not supported",
    '6984': "PIN Try Limit exceeded"
}

# define GET_DATA primitive tags
PIN_TRY_COUNTER = [0x9f, 0x17]
ATC = [0x9f, 0x36]
LAST_ATC = [0x9f, 0x13]
LOG_FORMAT = [0x9f, 0x4f]

# define TAGs after BER-TVL decoding
BER_TLV_AIP = 0x02
BER_TLV_AFL = 0x14


def textprint(data):
    index = 0
    out = ''

    while index < len(data):
        if data[index] >= 0x20 and data[index] < 0x7f:
            out += chr(data[index])
        else:
            out += '.'
        index += 1
    print out


def hexprint(data):
    index = 0
    out = ''
    while index < len(data):
        # print '%02x' % data[index],
        out += '%02x ' % data[index]
        index += 1
    d['output'] = out
    "{cyan}{output}{white}".format(**d)
    print

def isbinary(data):
    index= 0

    while index < len(data):
        if data[index] < 0x20 or data[index] > 0x7e:
            return True
        index += 1
    return False


def decode_pse(data):
    "decode the main PSE select response"
    index = 0
    indent = ''
    out = ''
    valuelength = 0
    if OutputFiles:
        file = open('%s-PSE.HEX' % CurrentAID, 'w')
        for n in range(len(data)):
            file.write('%02X' % data[n])
        file.flush()
        file.close()

    if RawOutput:
        hexprint(data)
        textprint(data)
        return

    while index < len(data):
        try:
            tag = data[index]
            TAGS[tag]
            taglen = 1
        except:
            try:
                tag = data[index] * 256 + data[index + 1]
                TAGS[tag]
                taglen = 2
            except:
                print "{red}".format(**d)
                print indent + '  Unrecognised TAG:',
                print "{white}".format(**d)
                hexprint(data[index:])
                return
        d['tag'] = "%0x:" % tag
        d['data'] = TAGS[tag][0]
        d['indent'] = indent
        print "{indent} {green}{tag}{yellow}{data}{white}".format(**d)
        if TAGS[tag][2] == VALUE:
            itemlength = 1
            offset = 0
            valuelength = 1
        else:
            if (data[index + taglen] & 0x80 == 0):
                itemlength = data[index + taglen]
                offset = 1
                d['itemlength'] = '(%d bytes):' % itemlength
                print "{green}{itemlength}{white}".format(**d)
                valuelength = 1
                # print '(%d bytes):' % itemlength,
            else:
                valuebytelen = data[index + taglen] & 0x7F
                itemlength = 0
                for i in range(1, valuebytelen + 1):
                    currentval = data[index + taglen + i]
                    itemlength = (itemlength << 8) + currentval
                offset = 1 + valuebytelen
                d['itemlength'] = '(%d bytes):' % itemlength
                valuelength = valuebytelen + 1
                print "{green}{itemlength}{white}".format(**d)
                # print '(%d bytes):' % itemlength,
        # store CDOLs for later use
        if tag == CDOL1:
            Cdol1 = data[index + taglen:index + taglen + itemlength + 1]
        if tag == CDOL2:
            Cdol2 = data[index + taglen:index + taglen + itemlength + 1]
        out = ''
        mixedout = []
        while itemlength > 0:
            if TAGS[tag][1] == BER_TLV:
                print 'skipping BER-TLV object!'
                return
                # decode_ber_tlv_field(data[index + taglen + offset:])
            if TAGS[tag][1] == BINARY or TAGS[tag][1] == VALUE:
                out += '%02x' % data[index + taglen + offset]
                # if TAGS[tag][2] != TEMPLATE or Verbose:
                # out += '%02x' % data[index + taglen + offset]
                # d['data'] = '%02x' % data[index + taglen + offset],
                # print "{yellow}{data}{white}".format(**d)
                # out += '%02x' % data[index + taglen + offset]
                # print '%02x' % data[index + taglen + offset],
            else:
                if TAGS[tag][1] == NUMERIC:
                    out += '%02x' % data[index + taglen + offset]
                else:
                    if TAGS[tag][1] == TEXT:
                        out += "%c" % data[index + taglen + offset]
                    if TAGS[tag][1] == MIXED:
                        mixedout.append(data[index + taglen + offset])
            itemlength -= 1
            offset += 1
        d['out'] = out
        print "{cyan}{out}{white}".format(**d)
        if TAGS[tag][1] == MIXED:
            if isbinary(mixedout):
                hexprint(mixedout)
            else:
                textprint(mixedout)
        if TAGS[tag][1] == BINARY:
            print
        if TAGS[tag][1] == TEXT or TAGS[tag][1] == NUMERIC:
            # print out,
            if tag == 0x9f42 or tag == 0x5f28:
                print '(' + ISO3166CountryCodes['%03d' % int(out)] + ')'
            else:
                print

        if TAGS[tag][2] == ITEM:
            # print "{cyan}{out}{white}".format(**d)
            index += data[index + taglen + (valuelength - 1)] + taglen + valuelength
        else:
            index += taglen + valuelength
        #           if TAGS[tag][2] != VALUE:
    #               indent += '   '
    indent = ''
