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
    from seedkeeper.Client import Client
    from seedkeeper.handler import HandlerTxt, HandlerSimpleGUI


if (len(sys.argv)>=2) and (sys.argv[1]in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)

logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

#handler= HandlerTxt()
handler= HandlerSimpleGUI(logger.getEffectiveLevel())
client= Client(None, handler, logger.getEffectiveLevel())
cc = CardConnector(client, logger.getEffectiveLevel())
time.sleep(1) # give some time to initialize reader...

################

client.card_init_connect()

while(True):
    event= handler.main_menu()
    logger.debug("Event: "+ str(event))
    
    # todo: switch seedkeeper cards...
    #todo: backup seedkeeper
    if event == 'Generate a new seed':
        client.generate_seed()    
    elif  event == 'Import a Secret':
        client.import_secret()
    elif event == 'Export a Secret':
        handler.export_secret()
    elif event == 'List Secrets':
        handler.list_headers()
    elif event == 'Get logs':
        handler.logs_menu()
    elif event == 'About':
        handler.about_menu()
    elif event == 'Quit':
        break;
    else: 
        logger.debug("Unknown event: "+ str(event))
        break;

