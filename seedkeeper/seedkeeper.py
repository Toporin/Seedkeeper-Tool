import json
import time
import logging
import sys
#import traceback
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
    from satochip_bridge.Client import Client
    from satochip_bridge.handler import HandlerTxt, HandlerSimpleGUI


if (len(sys.argv)>=2) and (sys.argv[1]in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)

logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

handler= HandlerTxt()
#handler= HandlerSimpleGUI(logger.getEffectiveLevel())
client= Client(None, handler, logger.getEffectiveLevel())
cc = CardConnector(client, logger.getEffectiveLevel())
time.sleep(1) # give some time to initialize reader...

#try:
cc.client.card_init_connect()
logger.debug("\n\n\n")

#cc.seedkeeper_list_secret_headers()
logger.debug("\n\n\n")

id=0
seed_size= 64
export_rights= 0x01
label= "My masterseed #12 32bytes export allowed"
#(response, sw1, sw2, id)= cc.seedkeeper_generate_masterseed(seed_size, export_rights, label)
logger.debug("\n\n\n")

#bip39= "chunk hat mirror there suit burst salute patch trumpet drastic spare pilot laptop smile hurry bleak friend rude divide melody iron fame dynamic parrot"
bip39= 255*"Z"
secret= list(bip39.encode("utf-8"))
secret= [len(secret)]+secret
secret_type= 0x30
export_rights= 0x01
label= 127*"A"
(id, fingerprint)=  cc.seedkeeper_import_plain_secret(secret_type, export_rights, label, secret)
logger.debug("\n\n\n")

# bip39="A"
# while(True):
    # secret= list(bip39.encode("utf-8"))
    # secret= [len(secret)]+secret
    # secret_type= 0x30
    # export_rights= 0x01
    # label= "test"
    # (id, fingerprint)=  cc.seedkeeper_import_plain_secret(secret_type, export_rights, label, secret)
    # logger.debug("--------------------------------------------------------------------------------------------------------------------")
    # secret_dic=cc.seedkeeper_export_plain_secret(id)
    # logger.debug("==========================================================")
    # bip39+="A"

logger.debug("\n\n\n")
    
    
    
#secret_dic=cc.seedkeeper_export_plain_secret(id)
logger.debug("\n\n\n")



cc.seedkeeper_list_secret_headers()
logger.debug("\n\n\n")
    
    
# except Exception as e:
    # #cc.client.request('show_error','[handleConnected] Exception:'+repr(e))
    # logger.warning('Exception:'+repr(e))



## TEST TODO ###
# Check integrity import => export
# test max size
























