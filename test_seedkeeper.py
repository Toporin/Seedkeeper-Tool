#!/usr/bin/env python3
#
# Copyright (c) 2020 Toporin - https://github.com/Toporin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

# Run with: python3 -m unittest -v test_seedkeeper.py

import time
import logging
import random
import unittest
from os import urandom

from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

try: 
    from Client import Client
    from handler import HandlerTxt, HandlerSimpleGUI
except Exception as e:
    print('ImportError: '+repr(e))
    from seedkeeper.Client import Client
    from seedkeeper.handler import HandlerTxt, HandlerSimpleGUI


logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )


class SeedKeeperTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        
        # constants
        cls.LOG_SIZE=4
        cls.INS_GENERATE_MASTERSEED= 0xA0
        cls.INS_IMPORT_PLAIN_SECRET= 0xA1
        cls.INS_EXPORT_PLAIN_SECRET= 0xA2
        cls.INS_VERIFY_PIN= 0x42
        #initialize list of secrets
        cls.id=[]
        cls.pin= list(bytes("123456", "utf-8"))
        cls.wrong_pin= list(bytes("0000", "utf-8"))
        
        #setup seedkeeper
        handler= HandlerTxt() #HandlerSimpleGUI(logger.getEffectiveLevel())
        client= Client(None, handler, logger.getEffectiveLevel())

        logger.info("Initialize new CardConnector...")
        cls.cc = CardConnector(client, logger.getEffectiveLevel())
        time.sleep(1) # give some time to initialize reader...
        logger.info("ATR: "+str(cls.cc.card_get_ATR()))
    
        # check setup
        while(cls.cc.card_present):
            (response, sw1, sw2, d)=cls.cc.card_get_status()
            
            # check version
            if  (cls.cc.setup_done):
                #v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}") #debugSatochip
                if (cls.cc.needs_secure_channel):
                    cls.cc.card_initiate_secure_channel()
                break 
                
            # setup device (done only once)
            else:
                # setup pin
                pin_0= cls.pin # bytes("123456", "utf-8")
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0= list(urandom(16)); 
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 0x0000 # RFU
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU
                
                #setup
                (response, sw1, sw2)=cls.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:       
                    logger.warning(f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    return
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
                    
                break
                
        # verify pin:
        try: 
            #cls.cc.card_verify_PIN()
            cls.cc.card_verify_PIN_deprecated(0, cls.pin)
        except RuntimeError as ex:
            logger.error(repr(ex))            
            return
        
        # get authentikey
        try:
            cls.authentikey=cls.cc.card_bip32_get_authentikey()
        except UninitializedSeedError as ex:
            logger.error(repr(ex))            
            return
        
##############

    def test_generate_masterseed(self):
        id=0
        seed_size= range(16, 65, 16) #64
        for size in seed_size:
            export_rights= 0x01
            label= "Test: Mymasterseed  "+ str(size) + "bytes export-allowed"
            (response, sw1, sw2, id, fingerprint)= SeedKeeperTest.cc.seedkeeper_generate_masterseed(size, export_rights, label)
            self.assertEqual(sw1, 0x90)
            self.assertEqual(sw2, 0x00)
            
            # check logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_GENERATE_MASTERSEED)
            self.assertEqual(id1, id)
            self.assertEqual(id2, 0)
            self.assertEqual(res, 0x9000)
            
            # check fingerprint and export secret
            dict= SeedKeeperTest.cc.seedkeeper_export_plain_secret(id)
            self.assertEqual(dict['id'], id)
            self.assertEqual(dict['type'], 0x10)
            self.assertEqual(dict['export_rights'], export_rights)
            self.assertEqual(dict['fingerprint'], fingerprint) 
            self.assertEqual(dict['label'], label) 
            SeedKeeperTest.id+=[id]
                
            # test logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_PLAIN_SECRET)
            self.assertEqual(id1, id)
            self.assertEqual(id2, 0)
            self.assertEqual(res, 0x9000)
        
        
    def test_import_export_secret(self):
        bip39_12= "praise seed filter man vintage live circle flag zoo orphan feature right"
        bip39_18= "current later item champion riot seat second seven card evidence pause twice spread reason purity easily surprise split"
        bip39_24= "chunk hat mirror there suit burst salute patch trumpet drastic spare pilot laptop smile hurry bleak friend rude divide melody iron fame dynamic parrot"
        bip39s=[bip39_12, bip39_18, bip39_24]
        
        for bip39 in bip39s:
            secret= list(bip39.encode("utf-8"))
            secret= [len(secret)]+secret
            secret_type= 0x30
            export_rights= 0x01
            label= "Test: BIP39 seed with " + str(len(bip39.split(' '))) + " words export-allowed"
            (id, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_plain_secret(secret_type, export_rights, label, secret)
            
            dict= SeedKeeperTest.cc.seedkeeper_export_plain_secret(id)
            self.assertEqual(dict['id'], id)
            self.assertEqual(dict['type'], secret_type)
            self.assertEqual(dict['export_rights'], export_rights)
            self.assertEqual(dict['fingerprint'], fingerprint) 
            self.assertEqual(dict['label'], label) 
            self.assertEqual(dict['secret'], secret) 
            SeedKeeperTest.id+=[id]
            
            # TODO: try  to export non existent id
            
            # test SeedKeeper logging
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(True)
            self.assertTrue(len(logs)>=2)
            exp_log= logs[0]
            (ins, id1, id2, res)= exp_log
            self.assertEqual(len(exp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_PLAIN_SECRET)
            self.assertEqual(id1, id)
            self.assertEqual(id2, 0)
            self.assertEqual(res, 0x9000)
            imp_log= logs[1]
            (ins, id1, id2, res)= imp_log
            self.assertEqual(len(imp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_IMPORT_PLAIN_SECRET)
            self.assertEqual(id1, id)
            self.assertEqual(id2, 0)
            self.assertEqual(res, 0x9000)
            
    def test_verify_PIN(self):
        (response, sw1, sw2)= SeedKeeperTest.cc.card_verify_PIN_deprecated(0, SeedKeeperTest.wrong_pin)
        self.assertEqual(sw1, 0x63)
        (response, sw1, sw2)= SeedKeeperTest.cc.card_verify_PIN_deprecated(0, SeedKeeperTest.pin)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)
        # check logs
        (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
        self.assertTrue(len(logs)==1)
        (ins, id1, id2, res)= logs[0]
        self.assertEqual(ins, SeedKeeperTest.INS_VERIFY_PIN)
        self.assertEqual(id1, 0)
        self.assertEqual(id2, 0)
        self.assertEqual(res & 0xFF00, 0x6300)
        
    #TODO
    # test Block/Unblock pin
    
    
    
def __main__():
    unittest.main()

if __name__ == "__main__":
    __main__()

