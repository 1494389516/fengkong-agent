"""Apple App Attest assertions for PREVIOUSLY TRUSTED server-registered P256 keys.

Protocol: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
This does not register keys or validate Apple's certificate chain. Never accept
PEM from request data. Caller must atomically CAS returned counter with replay state.
SDK primary hash=SHA256(canonical payload); re-assertion hash=SHA256(server policy
reAttestationChallenge). Verify both in counter order when freshness is required.
The paired SDK configures authenticated enrollment callbacks and persists a key
only after server acceptance. Older SDK keys need reenrollment; merely supplying
a public key or a self-signed receipt does not establish Apple provenance.
Only classic 37-byte authenticator data is supported. Extensions fail closed until
validation-category and bundle-version policy support is implemented.
"""
import hashlib
import hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

class AssertionError(ValueError):
    """Malformed, mismatched, stale or invalid assertion."""


def _decode_assertion(raw):
    if not isinstance(raw,bytes) or not 1 <= len(raw) <= 16384:
        raise AssertionError('invalid assertion size')
    offset=0
    def take(size):
        nonlocal offset
        if size<0 or offset+size>len(raw): raise AssertionError('truncated CBOR')
        result=raw[offset:offset+size];offset+=size
        return result
    def header(expected):
        first=take(1)[0]
        if first>>5 != expected: raise AssertionError('unexpected CBOR type')
        info=first&31
        if info<24: return info
        if info not in (24,25,26,27): raise AssertionError('indefinite CBOR unsupported')
        size=int.from_bytes(take({24:1,25:2,26:4,27:8}[info]),'big')
        if size>16384: raise AssertionError('oversized CBOR field')
        return size
    if header(5)!=2: raise AssertionError('expected signature/authenticatorData map')
    result={}
    try:
        for _ in range(2):
            key=take(header(3)).decode('utf-8')
            if key in result: raise AssertionError('duplicate CBOR key')
            result[key]=take(header(2))
    except UnicodeDecodeError as exc: raise AssertionError('invalid CBOR text') from exc
    if offset!=len(raw) or set(result)!={'signature','authenticatorData'}:
        raise AssertionError('unknown or trailing assertion data')
    return result


def verify_assertion(assertion_bytes, public_key_pem, app_id, client_data_hash, previous_counter):
    """Return increasing counter; app_id=trusted Apple prefix+'.'+bundle identifier.

    Server reconstructs client_data_hash itself; never trust a provided digest.
    For re-attestation hash the pending server-issued challenge's original bytes.
    """
    if not isinstance(app_id,str) or not app_id or '.' not in app_id:
        raise AssertionError('invalid trusted app id')
    if not isinstance(client_data_hash,bytes) or len(client_data_hash)!=32:
        raise AssertionError('clientDataHash must be 32 bytes')
    if type(previous_counter) is not int or not 0 <= previous_counter <= 0xffffffff:
        raise AssertionError('invalid previous counter')
    assertion=_decode_assertion(assertion_bytes)
    auth=assertion['authenticatorData']
    if len(auth)!=37 or auth[32]&0xc0:
        raise AssertionError('unsupported authenticator data or extensions')
    if not hmac.compare_digest(auth[:32],hashlib.sha256(app_id.encode()).digest()):
        raise AssertionError('app id mismatch')
    counter=int.from_bytes(auth[33:37],'big')
    if counter<=previous_counter: raise AssertionError('assertion counter replay')
    try:
        key=serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key,ec.EllipticCurvePublicKey) or not isinstance(key.curve,ec.SECP256R1):
            raise AssertionError('registered key must be P-256')
        nonce=hashlib.sha256(auth+client_data_hash).digest()
        # Nonce is the digest of WebAuthn signed bytes; do not hash it twice.
        key.verify(assertion['signature'],nonce,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (ValueError,TypeError,InvalidSignature) as exc:
        raise AssertionError('invalid registered key or assertion signature') from exc
    return counter


def _cbor_object(raw):
    """Bounded definite-length CBOR subset used by Apple attestation and COSE."""
    if not isinstance(raw,bytes) or len(raw)>65536: raise AssertionError('CBOR size exceeded')
    pos=0;budget=512
    def read(depth=0):
        nonlocal pos,budget
        budget-=1
        if depth>12 or budget<0 or pos>=len(raw): raise AssertionError('invalid CBOR budget')
        head=raw[pos];pos+=1;major=head>>5;n=head&31
        if n>=24:
            widths={24:1,25:2,26:4,27:8}
            if n not in widths or pos+widths[n]>len(raw): raise AssertionError('unsupported CBOR length')
            size=widths[n];n=int.from_bytes(raw[pos:pos+size],'big');pos+=size
        if major in (0,1): return n if major==0 else -1-n
        if n>65536: raise AssertionError('CBOR length exceeded')
        if major in (2,3):
            if pos+n>len(raw): raise AssertionError('truncated CBOR')
            v=raw[pos:pos+n];pos+=n
            try:return v if major==2 else v.decode('utf-8')
            except UnicodeDecodeError as exc:raise AssertionError('invalid CBOR text') from exc
        if major==4:return [read(depth+1) for _ in range(n)]
        if major==5:
            result={}
            for _ in range(n):
                k=read(depth+1)
                if not isinstance(k,(str,int,bytes)) or k in result: raise AssertionError('invalid duplicate CBOR key')
                result[k]=read(depth+1)
            return result
        raise AssertionError('unsupported CBOR type')
    obj=read()
    if pos!=len(raw):raise AssertionError('trailing CBOR data')
    return obj


def _attestation_nonce(extension):
    def unwrap(raw,tag):
        if len(raw)<2 or raw[0]!=tag:raise AssertionError('invalid nonce DER tag')
        n=raw[1];offset=2
        if n&128:
            size=n&127
            if size not in (1,2) or len(raw)<2+size:raise AssertionError('invalid nonce DER length')
            n=int.from_bytes(raw[2:2+size],'big');offset+=size
        if offset+n!=len(raw):raise AssertionError('trailing nonce DER')
        return raw[offset:]
    return unwrap(unwrap(unwrap(extension,0x30),0xa1),0x04)


def verify_attestation(attestation_bytes, key_id, app_id, challenge, root_pem, *, environment='production', now=None):
    """Validate Apple-root chain + challenge binding and return registered public PEM.

    root_pem is an operator-pinned Apple App Attestation Root CA, never supplied by
    client. Software test CAs validate implementation only, not Apple authenticity.
    Supports classic iOS attestation; newer extensions/macOS ACL require additional
    policy validation and are rejected. Enrollment receipts must be retained by the
    caller if Apple fraud-metric receipt validation is required for deployment.
    """
    import base64,time
    from datetime import datetime,timezone
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa,padding
    if environment not in ('production','development') or not isinstance(challenge,bytes) or len(challenge)<32:
        raise AssertionError('invalid enrollment context')
    obj=_cbor_object(attestation_bytes)
    if not isinstance(obj,dict) or set(obj)!={'fmt','attStmt','authData'} or obj['fmt']!='apple-appattest':
        raise AssertionError('invalid Apple attestation format')
    statement=obj['attStmt'];auth=obj['authData']
    if not isinstance(statement,dict) or set(statement)!={'x5c','receipt'} or not isinstance(statement['receipt'],bytes) or not statement['receipt']:
        raise AssertionError('invalid Apple attestation statement')
    chain=statement['x5c']
    if not isinstance(chain,list) or not 2<=len(chain)<=3 or any(not isinstance(v,bytes) for v in chain):
        raise AssertionError('invalid certificate chain')
    try:
        certs=[x509.load_der_x509_certificate(v) for v in chain]
        root=x509.load_pem_x509_certificate(root_pem)
        now_dt=datetime.fromtimestamp(time.time() if now is None else now,timezone.utc)
        for cert in certs+[root]:
            if not cert.not_valid_before_utc<=now_dt<=cert.not_valid_after_utc:raise AssertionError('expired certificate')
        # All CAs are required to assert BasicConstraints; leaf must not be a CA.
        if certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AssertionError('credential certificate cannot be CA')
        for i,cert in enumerate(certs):
            issuer=certs[i+1] if i+1<len(certs) else root
            constraints=issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if cert.issuer!=issuer.subject or not constraints.ca:raise AssertionError('invalid issuer')
            if constraints.path_length is not None and i>constraints.path_length:raise AssertionError('CA path length exceeded')
            public=issuer.public_key()
            if isinstance(public,ec.EllipticCurvePublicKey): public.verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(cert.signature_hash_algorithm))
            elif isinstance(public,rsa.RSAPublicKey): public.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
            else:raise AssertionError('unsupported CA key')
        leaf=certs[0];public=leaf.public_key()
        if not isinstance(public,ec.EllipticCurvePublicKey) or not isinstance(public.curve,ec.SECP256R1):raise AssertionError('credential must be P256')
        nonce=_attestation_nonce(leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier('1.2.840.113635.100.8.2')).value.value)
        expected=hashlib.sha256(auth+hashlib.sha256(challenge).digest()).digest()
        if not hmac.compare_digest(nonce,expected):raise AssertionError('enrollment challenge mismatch')
        identifier=base64.b64decode(key_id,validate=True)
        point=public.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        if not hmac.compare_digest(hashlib.sha256(point).digest(),identifier):raise AssertionError('credential key id mismatch')
    except (ValueError,TypeError,InvalidSignature,x509.ExtensionNotFound) as exc:
        raise AssertionError('invalid Apple certificate evidence') from exc
    if not isinstance(auth,bytes) or len(auth)<55 or not auth[32]&0x40 or auth[32]&0x80:
        raise AssertionError('unsupported attestation authenticator format')
    if auth[:32]!=hashlib.sha256(app_id.encode()).digest() or auth[33:37]!=b'\0'*4:
        raise AssertionError('attestation app/counter mismatch')
    expected_guid=b'appattest'+b'\0'*7 if environment=='production' else b'appattestdevelop'
    if auth[37:53]!=expected_guid:raise AssertionError('attestation environment mismatch')
    size=int.from_bytes(auth[53:55],'big')
    if size!=32 or auth[55:55+size]!=identifier:raise AssertionError('credential id mismatch')
    cose=_cbor_object(auth[55+size:])
    nums=public.public_numbers()
    if not isinstance(cose,dict) or cose.get(1)!=2 or cose.get(3)!=-7 or cose.get(-1)!=1 or cose.get(-2)!=nums.x.to_bytes(32,'big') or cose.get(-3)!=nums.y.to_bytes(32,'big'):
        raise AssertionError('COSE key mismatch')
    return public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
