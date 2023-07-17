# -*- coding: utf-8 -*-
from zeep import Client 
import xmltodict

class Request:

    env                 = "developer"
    service             = None
    function            = None
    arg                 = None
    wsdl                = {
        "developer"     : "https://maullin.sii.cl"
    }

    def __init__(self, 
                 data   : dict  = {}):
        try:
            (service   := data.get("service"))
            (function  := data.get("function"))
            (arg       := data.get("arg"))

            self.service    = service
            self.function   = function
            self.arg        = arg
        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
        
    def get(self) -> dict:
        try:
            if self.service == None:
                return {
                    "errors"    : True,
                    "Message"   : "'service' is NULL"
                }
            
            if self.function == None:
                return {
                    "errors"    : True,
                    "Message"   : "'function' is NULL"
                }
            
            client = Client(f"{self.wsdl['developer']}/DTEWS/{self.service}.jws?WSDL")

            if self.arg != None:
                return xmltodict.parse(getattr(client.service, self.function)(*self.arg))

            return xmltodict.parse(getattr(client.service, self.function)())

        except Exception as ex:
            print({
                "errors"    : False,
                "message"   : f"Server internal: {ex}"
            })
            exit()
