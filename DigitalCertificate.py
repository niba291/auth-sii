# -*- coding: utf-8 -*-
import os
import datetime
import base64
import xmltodict
import hashlib
# =======================================================================================================================
from Tools                                          import Tools
# =======================================================================================================================
from cryptography.hazmat.primitives.serialization   import pkcs12, Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric      import padding
from cryptography.hazmat.primitives                 import hashes
from cryptography.x509.oid                          import NameOID, ExtensionOID
from tempfile                                       import NamedTemporaryFile
from datetime                                       import datetime

class DigitalCertificate:

    password                                = None
    cert                                    = None
    additionalCertificates                  = None
    certContent                             = None
    privateKey                              = None
    password                                = None
    path                                    = f"certificate"

    def __init__(self):
        try:
            self.privateKey, self.cert, self.additionalCertificates = pkcs12.load_key_and_certificates(open(self.path, "rb").read(), password = self.password.encode())
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def getId(self) -> dict:
        try:
            id              = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)

            if id == []:
                id          = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value[0].value.decode("utf-8").replace("\x16\n", "")
            else:
                id          = id[0].value

            return {
                "errors"    : False,
                "message"   : {
                    "all"   : id,
                    "rut"   : id.split("-")[0],
                    "dv"    : id.split("-")[1]
                }
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()   

    def getOwner(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
    
    def getCompany(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()

    def getEmail(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def getFrom(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.cert.not_valid_before
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def getTo(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.cert.not_valid_after
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def getExpiration(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : self.getTo()["message"] - datetime.datetime.today()
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
    
    def getModulus(self) -> dict:
        try:        
            return {
                "errors"    : False,
                "message"   : base64.b64encode(self.privateKey.private_numbers().public_numbers.n.to_bytes(256, "big")).decode()
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def getExponent(self) -> dict:
        try:        
            return {
                "errors"    : False,
                "message"   : base64.b64encode(self.privateKey.private_numbers().public_numbers.e.to_bytes(3, "big")).decode()
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()

    def getPrivateExponent(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : base64.b64encode(self.privateKey.private_numbers().d.to_bytes(256, "big")).decode(),
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
    
    def getCertigicate(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : Tools().wordwrap(self.cert.public_bytes(encoding = Encoding.PEM).decode().replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", ""), width = 72, separator = "\n")
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()

    def getPrivateKey(self) -> dict:
        try:
            return {
                "errors"    : False,
                "message"   : Tools().wordwrap(self.privateKey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode().replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", ""), width = 72, separator = "\n")
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()

    def setSignature(self, 
                     reference      : str   = "", 
                     document       : str   = "", 
                     toXml          : dict  = {"enabled" : False, "pretty": False, "full_document": False}, 
                     xmlnsXsi       : bool  = False, 
                     removeXmlnsXsi : bool  = True) -> str or dict:
        try:            

            formatSignature                                                                 = {
                "Signature"                                                                 : {
                    "@xmlns"                                                                : "http://www.w3.org/2000/09/xmldsig#",
                    "SignedInfo"                                                            : {
                        "@xmlns"                                                            : "http://www.w3.org/2000/09/xmldsig#",
                        "@xmlns:xsi"                                                        : "http://www.w3.org/2001/XMLSchema-instance",
                        "CanonicalizationMethod"                                            : {
                            "@Algorithm"                                                    : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "SignatureMethod"                                                   : {
                            "@Algorithm"                                                    : "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                        },
                        "Reference"                                                         : {
                            "@URI"                                                          : "",
                            "Transforms"                                                    : {
                                "Transform"                                                 : {
                                    "@Algorithm"                                            : "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                                }
                            },
                            "DigestMethod"                                                  : {
                                "@Algorithm"                                                : "http://www.w3.org/2000/09/xmldsig#sha1"
                            },
                            "DigestValue"                                                   : None
                        }
                    },
                    "SignatureValue"                                                        : None,
                    "KeyInfo"                                                               : {
                        "KeyValue"                                                          : {
                            "RSAKeyValue"                                                   : {
                                "Modulus"                                                   : None,
                                "Exponent"                                                  : None
                            }
                        },
                        "X509Data"                                                          : {
                            "X509Certificate"                                               : None
                        }
                    }
                }
            }

            if not xmlnsXsi:
                del formatSignature["Signature"]["SignedInfo"]["@xmlns:xsi"]
            
            if isinstance(document, str):
                document    = document.encode().decode("ISO-8859-1").encode()

            digest                                                                          = hashlib.sha1(document).digest()
            certificate                                                                     = self.getCertigicate()["message"]
            formatSignature["Signature"]["SignedInfo"]["Reference"]["@URI"]                 = reference
            formatSignature["Signature"]["SignedInfo"]["Reference"]["DigestValue"]          = base64.b64encode(digest).decode()
            formatSignature["Signature"]["KeyInfo"]["X509Data"]["X509Certificate"]          = certificate
            formatSignature["Signature"]["KeyInfo"]["KeyValue"]["RSAKeyValue"]["Modulus"]   = self.getModulus()["message"]
            formatSignature["Signature"]["KeyInfo"]["KeyValue"]["RSAKeyValue"]["Exponent"]  = self.getExponent()["message"]

            signaInfo                                                                       = xmltodict.unparse({"SignedInfo": formatSignature["Signature"]["SignedInfo"]}, pretty = False, full_document = False)
            signature                                                                       = self.privateKey.sign(
                signaInfo.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )

            formatSignature["Signature"]["SignatureValue"]                                  = base64.b64encode(signature).decode()
            
            if removeXmlnsXsi:
                del formatSignature["Signature"]["SignedInfo"]["@xmlns"]

            if xmlnsXsi:
                del formatSignature["Signature"]["SignedInfo"]["@xmlns:xsi"]

            return (toXml["enabled"] and xmltodict.unparse(formatSignature, pretty = toXml["pretty"], full_document = toXml["full_document"])) or formatSignature
        except Exception as ex:
            raise Exception(f"Error: {ex}")