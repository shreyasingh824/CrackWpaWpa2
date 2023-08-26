import hmac, hashlib, binascii

def hmac_sha1(key, msg): return hmac.new(key, msg, hashlib.sha1).digest()
def to_mac(addr): return ':'.join(addr[i:i+2] for i in range(0, len(addr), 2))
def PRF_512(key, A, B):
    result = b''  # Initialize an empty bytes object
    for i in range(4):
        intermediate = A + bytes([0]) + B + bytes([i])  # Construct bytes with appropriate parts
        hmac_result = hmac_sha1(key, intermediate)
        result += hmac_result  # Concatenate the hmac result to the result bytes
    return result[:64]

def a2b(s): return binascii.a2b_hex(s)
def b2a(by): return binascii.b2a_hex(by).decode('utf-8')

EAPOL1 = a2b("38d57a8cfbcff6c3b618701e888e0203005f02008a00100000000000000001c71a7a7eedc3c8dc9cb8625f2081b33af0adb3aba8107ff64813c07232e49f9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
EAPOL2 = a2b("f6c3b618701e38d57a8cfbcf888e0103007502010a000000000000000000016946beb2b299080d70d04be64fcf478988e69ae0494349345f2c992d79d8cc2f000000000000000000000000000000000000000000000000000000000000000088d46df1431e6d4d7043bb0f0efc4aed001630140100000fac040100000fac040100000fac020000")
SSID = "OPPO A5 2020"
PASS = "i7ut6j37"

XAUTH = a2b("888E")
if EAPOL1[0:6] == EAPOL2[6:12] and EAPOL2[0:6] == EAPOL1[6:12] and EAPOL1[12:14] == XAUTH and EAPOL1[12:14] == XAUTH:
    HAVEPTK = 8   # have 'pairwise' key
    VER_WPA = 2   # WPA2 means using 'SHA1' (vs MD5)
    if EAPOL1[20] & 8 == HAVEPTK and EAPOL1[20] % 8 == VER_WPA and EAPOL2[20] & 8 == HAVEPTK and EAPOL2[20] % 8 == VER_WPA:
        R1 = EAPOL1[31:63]      # random 1 (AP nonce)
        R2 = EAPOL2[31:63]      # random 2 (STA nonce)
        M1 = EAPOL2[0:6]        # MAC 1 (AP MAC)
        M2 = EAPOL1[0:6]        # MAC 2 (STA MAC)

        # Generate all keys
        PMK = hashlib.pbkdf2_hmac('sha1', PASS.encode('utf-8'), SSID.encode('utf-8'), 4096, 32)
        PTK = PRF_512(PMK, b"Pairwise key expansion", min(M1, M2) + max(M1, M2) + min(R1, R2) + max(R1, R2))
        KCK = PTK[0:16]

        # try to validate the MIC in EAPoL message #2 is correct
        MICCALC  = hmac_sha1(KCK, EAPOL2[14:95] + a2b("00000000000000000000000000000000") + EAPOL2[111:])[0:16]
        MICFOUND = EAPOL2[95:111]

        print("SSID/PASS: ", SSID, "/", PASS)
        print("PMK:       ", b2a(PMK))
        print("AP-MAC:    ", to_mac(b2a(M1)))
        print("STA-MAC:   ", to_mac(b2a(M2)))
        print("AP-NONCE:  ", b2a(R1))
        print("STA-NONCE: ", b2a(R2))
        print("KCK:       ", b2a(KCK))
        print("MIC-found: ", b2a(MICFOUND))
        print("MIC-calc:  ", b2a(MICCALC))
        print("Result:    ", "OK: EAPoL message #2 validated" if MICFOUND == MICCALC else "ERROR: MIC does not match")
    else:
        print("***ERROR: Did not find WPA2/PTK EAPoL messages")
else:
    print("***ERROR: Problem validated Ethernet frames. Do EAPOL1 and EAPOL2 both include the Ethernet headers?")

