#!/usr/bin/env python
"""
TODO:
    1. Add try catch for operations that can fail, esp file reads and writes
    2. Read defaults from a config file
    3. Get configuration from a configuration file
"""
from OpenSSL import crypto
import jks

def generate_private_key(keytype=crypto.TYPE_RSA, bits=2048):
    """
    Generate a key pair of the given type, with the given number of bits.

    :param keytype: The key type.
    :type type: :py:data:`TYPE_RSA` or :py:data:`TYPE_DSA`

    :param bits: The number of bits.
    :type bits: :py:data:`int` ``>= 0``

    :raises TypeError: If :py:data:`type` or :py:data:`bits` isn't
        of the appropriate type.
    :raises ValueError: If the number of bits isn't an integer of
        the appropriate size.

    :return: OpenSSL.crypto.PKey instance
    """
    # declare key encryption types
    TYPE_DSA = crypto.TYPE_DSA
    TYPE_RSA = crypto.TYPE_RSA
    # Create key
    key = crypto.PKey()
    key.generate_key(keytype, bits)
    return key

def create_csr(cn, key, altnames=[]):
    """
    TODO: Read these attributtes from a file, like opensl.cnf
    """
    C  = 'IN'
    ST = 'Karnataka'
    L  = 'Bangalroe'
    O  = 'ACME Enterprises'
    OU = 'Support'
   
    if 'DNS:{0}'.format(cn) in altnames:
      altname_str = ','.join(altnames)
    else:
      altnames.append('DNS:{0}'.format(cn))
      altname_str = ','.join(altnames)
    
    base_constraints = ([
                 crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
                 crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
                 crypto.X509Extension("subjectAltName", False, altname_str)
                 ])
    req = crypto.X509Req()
    req.add_extensions(base_constraints)
    req.sign(key,"sha256")
    return req

def write_private_key(key,filetype=crypto.FILETYPE_PEM,cipher=None,passphrase=None,outfile='/tmp/out.pem'):
    if passphrase and filetype != crypto.FILETYPE_PEM:
      raise Exception(
        "passphrase is only supported for PEM encoded private keys")

    open(outfile, "a+").write(crypto.dump_privatekey(filetype, key, cipher, passphrase))

def write_csr(req,filetype=crypto.FILETYPE_PEM,outfile='/tmp/out.pem'):
    open(outfile, "a+").write(crypto.dump_certificate_request(filetype, req))

def write_files(w_object,filetype=crypto.FILETYPE_PEM,cipher=None,passphrase=None,outfile='/tmp/out.pem'):
    # Declare encoding for key, req and cert files
    FILETYPE_ASN1 = crypto.FILETYPE_ASN1
    FILETYPE_PEM  = crypto.FILETYPE_PEM
    FILETYPE_TEXT = crypto.FILETYPE_TEXT
    
    # Check what object we are passed to write
    if isinstance(w_object, crypto.X509Req):
       write_csr(w_object,filetype,outfile)

    if isinstance(w_object, crypto.PKey):   
       write_private_key(w_object,filetype, cipher, passphrase, outfile)


def write_jks(key, cert, keystorepass='changeme', outfile='/tmp/out.jks'):
   """
   key: pyopenssl PKey object
   cert: pyopenssl x509 object
   TODO: sanitize, sanitize.... Too many assumptions
   """
   try:
     cn = dict(crypto.X509Name(cert.get_subject()).get_components())['CN']
   except:
     print "Warning: could not get CN from certificate, setting CN=myhost.mydomain"
     cn = "myhost.mydomain"

   asn1key  = crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, key)
   asn1cert = crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
   jks_alias = cn.lower()
   pke = jks.PrivateKeyEntry.new(jks_alias, [asn1cert], asn1key, 'rsa_raw')
   keystore = jks.KeyStore.new('jks', [pke])
   keystore.save(outfile, keystorepass)
