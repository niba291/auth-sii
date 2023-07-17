# -*- coding: utf-8 -*-
from DigitalCertificate import DigitalCertificate
# =======================================================================================================================
from Request import Request
# =======================================================================================================================
import xmltodict
# =======================================================================================================================

class Auth:

    def getSeed(self) -> dict:

        try:
            response        = Request({
                "service"   : "CrSeed",
                "function"  : "getSeed"
            }).get()

            if "SII:RESPUESTA" not in response:
                return {
                    "errors"    : True,
                    "message"   : "Not found SII:RESPUESTA"
                }
            
            response        = response["SII:RESPUESTA"]

            if response["SII:RESP_HDR"]["ESTADO"] != "00":
                return {
                    "errors"    : True,
                    "message"   : f"Error Sii: {response['SII:RESP_BODY']}"
                }
            
            return {
                "errors"    : False,
                "message"   : response["SII:RESP_BODY"]["SEMILLA"]
            }
        
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
    
    def getToken(self, 
                 digitalCertificate   : DigitalCertificate      = DigitalCertificate()) -> dict:
        try: 
            document                                            = {
                "getToken"          : {
                    "item"          : {
                        "Semilla"   : None
                    }
                }
            }

            document["getToken"]["item"]["Semilla"]     = self.getSeed()["message"]
            signature                                   = digitalCertificate.setSignature(
                document                                = xmltodict.unparse(document, pretty = True, full_document = False).replace("\t", "  ").encode(),
                toXml                                   = {
                    "enabled"                           : True,
                    "pretty"                            : False,
                    "full_document"                     : False
                },
                removeXmlnsXsi                          = False 
            )

            document["getToken"]["#text"]               = "{Signature}"
            xml                                         = xmltodict.unparse(
                document, 
                pretty          = True, 
                full_document   = False
            ).replace("\t", "  ").replace("{Signature}", signature)

            response                                    = Request({
                "service"                               : "GetTokenFromSeed",
                "function"                              : "getToken",
                "arg"                                   : [xml]
            }).get()

            if "SII:RESPUESTA" not in response:
                return {
                    "errors"    : True,
                    "message"   : "Not found SII:RESPUESTA"
                }
            
            response        = response["SII:RESPUESTA"]

            if response["SII:RESP_HDR"]["ESTADO"] != "00":
                return {
                    "errors"    : True,
                    "message"   : f"Error Sii: {response['SII:RESP_HDR']}"
                }
            
            document["getToken"]["#text"]
            document["getToken"]["Signature"]   = signature

            return {
                "errors"        : False,
                "message"       : {
                    "token"     : response["SII:RESP_BODY"]["TOKEN"],
                    "json"      : document,
                    "xml"       : xml
                }
            }
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()