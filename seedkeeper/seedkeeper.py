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

# print("DEBUG START seedkeeper.py ")
# print("DEBUG START seedkeeper.py __name__: "+__name__)
# print("DEBUG START seedkeeper.py __package__: "+str(__package__))

try: 
    from client import Client
    from handler import HandlerSimpleGUI
except Exception as e:
    print('seedkeeper importError: '+repr(e))
    from seedkeeper.client import Client
    from seedkeeper.handler import HandlerSimpleGUI
                
# to run from source, in parent folder: python3 -m  seedkeeper.py -v 
# alternatively, also in parent folder: python3  seedkeeper/seedkeeper.py -v 

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

while(True):
        
    event= handler.main_menu()
    logger.debug("Event: "+ str(event))
    
    if event == 'Generate_new_seed':
        client.generate_seed()    
    elif  event == 'import_secret': 
        client.import_secret()
    elif event ==  'export_secret': 
        handler.export_secret()
    elif event == 'make_backup':
        handler.make_backup()
    elif event == 'list_secrets':
        handler.list_headers()
    elif event == 'get_logs':
        handler.logs_menu()
    elif event == 'about':
        handler.about_menu()
    elif event == 'help':
        handler.help_menu()
    elif event == 'quit':
        break;
    else: 
        logger.debug("Unknown event: "+ str(event))
        break;

# print("DEBUG END seedkeeper.py ")
