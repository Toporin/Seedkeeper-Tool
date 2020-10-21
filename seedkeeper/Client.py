import threading
import logging
import json
from os import urandom
from queue import Queue 

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION
from pysatochip.version import SEEDKEEPER_PROTOCOL_MAJOR_VERSION, SEEDKEEPER_PROTOCOL_MINOR_VERSION, SEEDKEEPER_PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
               
class Client:

    def __init__(self, cc, handler, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.handler = handler
        self.handler.client= self
        self.queue_request= Queue()
        self.queue_reply= Queue()
        self.cc= cc
        self.truststore=[]
        self.new_card_present= False
    
    def request_threading(self, request_type, *args):
        logger.debug('Client request: '+ str(request_type))
        
        # bypass queue-based data exchange between main GUI thread and   
        # server thread when request comes directly from the main thread.
        if threading.current_thread() is threading.main_thread():
            #TODO: check if handler exist
            logger.debug('In main thread:')
            method_to_call = getattr(self.handler, request_type)
            #logger.debug('Type of method_to_call: '+ str(type(method_to_call)))
            #logger.debug('Method_to_call: '+ str(method_to_call))
            reply = method_to_call(*args)
            return reply 
        
        # we use a queue to exchange request between the server thread and the main (GUI) thread
        self.queue_request.put((request_type, args))
        logger.debug('In second thread:')
        
        # Get some data 
        try:
            #todo: check if several message are sent...
            #(reply_type, reply)= self.queue_reply.get(block=True, timeout=5)  #TODO: check if blocking
            (reply_type, reply)= self.queue_reply.get(block=True, timeout=None)  #TODO: check if blocking
            if (reply_type != request_type):
                # should not happen #todo: clean the queues
                RuntimeError("Reply mismatch during GUI handler notification!")
            else:
                return reply
        except Exception as exc:
            self.request('show_error', "[Client] Exception in request(): "+repr(exc))
            return None
            
    def request(self, request_type, *args):
        logger.debug('Client request: '+ str(request_type))
        
        # if self.handler is not None:                            
            # if (request_type=='update_status'):
                # reply = self.handler.update_status(*args) 
                # return reply 
            # elif (request_type=='show_error'):
                # reply = self.handler.show_error(*args) 
                # return reply 
            # elif (request_type=='show_success'):
                # reply = self.handler.show_success(*args) 
                # return reply 
            # elif (request_type=='show_message'):
                # reply = self.handler.show_message(*args) 
                # return reply 
            # elif (request_type=='get_passphrase'):
                # reply = self.get_passphrase(*args)
            # else:
                # reply = self.handler.show_error('Unknown request: '+str(request_type)) 
                # return reply 
        # else: 
            # _logger.info('[SatochipClient] self.handler is None! ')#debugSatochip
            # return None
        
        method_to_call = getattr(self.handler, request_type)
        #logger.debug('Type of method_to_call: '+ str(type(method_to_call)))
        #logger.debug('Method_to_call: '+ str(method_to_call))
        reply = method_to_call(*args)
        return reply 
        
    def PIN_dialog(self, msg):
        while True:
            (is_PIN, pin) = self.request('get_passphrase',msg)
            if (not is_PIN) or (pin is None): # if 'cancel' or windows closed
                 return (False, None)
            elif len(pin) < 4:
                msg = ("PIN must have at least 4 characters.") + \
                      "\n\n" + ("Enter PIN:")
            elif len(pin) > 64:
                msg = ("PIN must have less than 64 characters.") + \
                      "\n\n" + ("Enter PIN:")
            else:
                pin = pin.encode('utf8')
                return (True, pin)
    
    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while(True):
            (is_PIN, pin)= self.PIN_dialog(msg)
            if not is_PIN:
                return (False, None) #raise RuntimeError(('A PIN code is required to initialize the Satochip!'))
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if not is_PIN:
                return (False, None) #raise RuntimeError(('A PIN confirmation is required to initialize the Satochip!'))
            if (pin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (is_PIN, pin)
     
    def PIN_change_dialog(self, msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel):
        
        (is_PIN, oldpin)= self.PIN_dialog(msg_oldpin)
        if (not is_PIN):
            self.request('show_message', msg_cancel)
            return (False, None, None)

        # new pin
        while (True):
            (is_PIN, newpin)= self.PIN_dialog(msg_newpin)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            if (newpin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (True, oldpin, newpin)
    
    ########################################
    #             Setup functions                              #
    ########################################
    
    def card_init_connect(self):
        logger.debug('In card_init_connect()')
        #logger.info("ATR: "+str(self.cc.card_get_ATR()))
        #response, sw1, sw2 = self.card_select() #TODO: remove?
        
        # check setup
        while(self.cc.card_present):
            (response, sw1, sw2, d)=self.cc.card_get_status()
            
            # check version
            if  (self.cc.setup_done):
                #v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(('The version of your Satochip is higher than supported by SeedKeeper. You should update SeedKeeper to ensure correct functioning!')+ '\n' 
                                + f'    SeedKeeper version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {SEEDKEEPER_PROTOCOL_MAJOR_VERSION}.{SEEDKEEPER_PROTOCOL_MINOR_VERSION}')
                    self.request('show_error', msg)
                
                if (self.cc.needs_secure_channel):
                    self.cc.card_initiate_secure_channel()
                break 
                
            # setup device (done only once)
            else:
                # PIN dialog
                msg = ("Enter a new PIN for your Satochip:")
                msg_confirm = ("Please confirm the PIN code for your Satochip:")
                msg_error = ("The PIN values do not match! Please type PIN again!")
                (is_PIN, pin_0)= self.PIN_setup_dialog(msg, msg_confirm, msg_error)
                if not is_PIN:
                    #raise RuntimeError('A PIN code is required to initialize the Satochip!')
                    logger.warning('Initialization aborted: a PIN code is required to initialize the Satochip!')
                    self.request('show_error', 'A PIN code is required to initialize the Satochip.\nInitialization aborted!')
                    return False
                    
                pin_0= list(pin_0)
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
                (response, sw1, sw2)=self.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:       
                    logger.warning(f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    self.request('show_error', f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    return False
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
            
        # verify pin:
        try: 
            self.cc.card_verify_PIN()
        except RuntimeError as ex:
            logger.warning(repr(ex))
            self.request('show_error', repr(ex))
            return False
        
        # get authentikey
        try:
            authentikey=self.cc.card_bip32_get_authentikey()
        except UninitializedSeedError as ex:
            logger.warning(repr(ex))
            self.request('show_error', repr(ex))
            return False
            
        # return true if wizard finishes correctly 
        return True
        
############################
#    SEED WIZARD
############################    
    def generate_seed(self):
        event, values = self.handler.generate_new_seed()
        
        if event== 'Submit':
            logger.debug(values)
            label= values['label']
            export_rights= 0x01 if (values['export_rights']=='Export in clear allowed') else 0x02
            size= int(values['size'].split(' ')[0])
            
            (response, sw1, sw2, id, fingerprint)= self.cc.seedkeeper_generate_masterseed(size, export_rights, label)
            
            if (sw1==0x90 and sw2==0x00):
                self.handler.show_success(f'Seed generated with succes! \nId: {id} \nFingerprint: {fingerprint}')
            elif (sw1==0x9c and sw2==0x01):
                self.handler.show_error(f'Error during seed generation: no memory available!')
            elif (sw1==0x9c and sw2==0x04):
                self.handler.show_error(f'Error during seed generation: SeedKeeper is not initialized!')
            else:
                self.handler.show_error(f'Unknown error: sw1={hex(sw1)} sw2={hex(sw2)}')
        else:
            #cancel or None
            return
    
    
    def import_secret(self):
        
        event, values = self.handler.import_secret_menu()
        
        if event == 'Submit':
            try: 
                stype= values['type'][0] # values['type']           
                if stype== 'BIP39 seed':
                    (mnemonic, passphrase, seed, label, export_rights)= self.seed_wizard() #todo: check None
                    if mnemonic is None:
                        self.handler.show_message(f"Secret import aborted!")
                        return None
                    mnemonic_list= list(mnemonic.encode("utf-8"))
                    passphrase_list= list(passphrase.encode('utf-8'))
                    secret= [len(mnemonic_list)]+ mnemonic_list + [len(passphrase_list)] + passphrase_list
                    #(sid, fingerprint) = self.cc.seedkeeper_import_plain_secret(itype, export_rights, label, secret)
                    header= self.make_header(stype, export_rights, label)
                    secret_dic={'header':header, 'secret':secret}
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                    self.handler.show_success(f"Secret successfully imported with id {sid}")
                    return sid
                    
                elif stype== 'Electrum seed':
                    #TODO adapt wizard for electrum seeds?
                    self.handler.show_error(f"Not implement yet!")
                    return None
                    
                elif stype== 'MasterSeed':
                    event, values= self.handler.import_secret_masterseed()
                    if event == 'Submit':
                        masterseed= values['masterseed']
                        masterseed_list= list( bytes.fromhex(masterseed) )
                        secret= [len(masterseed_list)] + masterseed_list
                        #(sid, fingerprint) = self.cc.seedkeeper_import_plain_secret(itype, export_rights, label, secret) #deprecated
                        label= values['label']
                        export_rights= values['export_rights']
                        header= self.make_header(stype, export_rights, label)
                        secret_dic={'header':header, 'secret':secret}
                        (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                        self.handler.show_success(f"Secret successfully imported with id {sid}")
                        return sid
                    else:
                        self.handler.show_message(f"Operation cancelled")
                        return None
                        
                elif stype== 'Secure import from json':
                    self.import_secure_secret()
                    
                elif stype== 'Public Key':
                    event, values= self.handler.import_secret_pubkey()
                    if event == 'Submit':
                        pubkey= values['pubkey']
                        pubkey_list= list( bytes.fromhex(pubkey) )
                        secret= [len(pubkey_list)] + pubkey_list
                        #(sid, fingerprint) = self.cc.seedkeeper_import_plain_secret(itype, export_rights, label, secret)
                        label= values['label']
                        export_rights= values['export_rights']
                        header= self.make_header(stype, export_rights, label)
                        secret_dic={'header':header, 'secret':secret}
                        (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                        self.handler.show_success(f"Secret successfully imported with id {sid}")
                        return sid
                    else:
                        self.handler.show_message(f"Operation cancelled")
                        return None
                        
                elif stype== 'Authentikey from TrustStore':
                    if len(self.truststore)==0:
                        self.handler.show_message(f"No Authentikey found in TrustStore.\nOperation cancelled!")
                        return None
                    
                    event, values= self.handler.import_secret_authentikey()
                    if event == 'Submit':
                        authentikey= values['authentikey']
                        authentikey_list= list( bytes.fromhex(authentikey) )
                        secret= [len(authentikey_list)] + authentikey_list
                        #(sid, fingerprint) = self.cc.seedkeeper_import_plain_secret(itype, export_rights, label, secret)
                        label= values['label']
                        export_rights= values['export_rights']
                        header= self.make_header(stype, export_rights, label)
                        secret_dic={'header':header, 'secret':secret}
                        (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                        self.handler.show_success(f"Secret successfully imported with id {sid}")
                        return sid
                    else:
                        self.handler.show_message(f"Operation cancelled")
                        return None
                
                elif stype== 'Password':
                    event, values= self.handler.import_secret_password()
                    if event == 'Submit':
                        password= values['password']
                        password_list= list( password.encode('utf-8') )
                        secret= [len(password_list)] + password_list
                        #(sid, fingerprint) = self.cc.seedkeeper_import_plain_secret(itype, export_rights, label, secret)
                        label= values['label']
                        export_rights= values['export_rights']
                        header= self.make_header(stype, export_rights, label)
                        secret_dic={'header':header, 'secret':secret}
                        (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                        self.handler.show_success(f"Secret successfully imported with id {sid}")
                        return sid
                    else:
                        self.handler.show_message(f"Operation cancelled")
                        return None
                    
                else:
                    #should not happen
                    logger.error(f'In import_secret: wrong type for import: {stype}')
                    return None
            except Exception as ex:
                logger.error(f"Error during secret import: {ex}")
                self.handler.show_error(f"Error during secret import: {ex}")
                return None
                
        else: 
            return None
    
    def make_header(self, stype, export_rights, label):
        dic_type= {'BIP39 seed':0x30, 'Electrum seed':0x40, 'MasterSeed':0x10, 'Secure import from json':0x00, 
                                'Public Key':0x70, 'Authentikey from TrustStore':0x70, 'Password':0x90}
        dic_export_rights={'Export in plaintext allowed':0x01 , 'Export encrypted only':0x02}
        id=2*[0x00]
        itype= dic_type[stype]
        origin= 0x00
        export= dic_export_rights[export_rights]
        export_counters=3*[0x00]
        fingerprint= 4*[0x00]
        rfu=2*[0x00]
        label_size= len(label)
        label_list= list(label.encode('utf8'))
        header_list= id + [itype, origin, export] + export_counters + fingerprint + rfu + [label_size] + label_list
        header_hex= bytes(header_list).hex()
        return header_hex
     
    def import_secure_secret(self):
        logger.debug("In import_secure_secret()") #debugSatochip
        
        event, values = self.handler.import_secure_secret()
        
        if event == 'Import':
            secret_jsonstr= values['json']
            logger.debug('Secret_json:'+secret_jsonstr)
            try:
                secret_json= json.loads(secret_jsonstr)
            except json.JSONDecodeError as ex:
                logger.error(f"JSON parsing error during secure secret import: {ex}")
                self.handler.show_error(f"JSON parsing error during secret import: {ex}")
                return None
                
            # check if correct importer
            authentikey_importer=secret_json['authentikey_importer']
            authentikey= self.cc.card_bip32_get_authentikey().get_public_key_bytes(compressed=False).hex()
            if authentikey != authentikey_importer:
                self.handler.show_error('Authentikey mismatch: ' + authentikey_importer + 'should be' + authentikey)
                return None
            
            # get sid from authentikey_exporter
            authentikey_exporter=secret_json['authentikey_exporter']
            sid_pubkey=None
            headers= self.cc.seedkeeper_list_secret_headers()
            for header_dic in headers:
                if header_dic['type']==0x70:
                    #secret_dic= self.cc.seedkeeper_export_plain_secret(header_dic['id'])
                    secret_dic= self.cc.seedkeeper_export_secret(header_dic['id'], None) #export pubkey in plain
                    pubkey= secret_dic['secret_hex'][2:]
                    if pubkey== authentikey_exporter:
                        sid_pubkey= header_dic['id']
                        logger.debug('Found sid_pubkey: ' + str(sid_pubkey) )
                        break
            
            if sid_pubkey is not None:
                try:
                    secret_dic=secret_json['secrets'][0]
                    sid, fingerprint = self.cc.seedkeeper_import_secret(secret_dic, sid_pubkey)
                    self.handler.show_success('Key securely imported  successfully with id:' + str(sid))
                except (SeedKeeperError, UnexpectedSW12Error) as ex:
                    logger.error(f"Error during secure secret import: {ex}")
                    self.handler.show_error(f"Error during secret import: {ex}")
                    return None
            else:
                self.handler.show_error('Could not find a trusted pubkey matching '+ authentikey_exporter)
                return None
            
        else: 
            return None
    
    def seed_wizard(self): 
        logger.debug("In seed_wizard()") #debugSatochip
            
        from mnemonic import Mnemonic
        # state: state_choose_seed_action - state_create_seed -  state_request_passphrase - (state_confirm_seed)  - (state_confirm_passphrase) - state_abort
        # state: state_choose_seed_action - state_restore_from_seed - state_request_passphrase - state_abort
        state= 'state_choose_seed_action'    
        
        while (True):
            if (state=='state_choose_seed_action'):
                mnemonic= None
                passphrase= None
                seed= None
                needs_confirm= None
                use_passphrase= None
                (event, values)= self.handler.choose_seed_action()
                label= values['label']
                export_rights= values['export_rights']
                if (event =='Next') and (values['create'] is True):
                    state='state_create_seed'
                elif (event =='Next') and (values['restore'] is True):
                    state= 'state_restore_from_seed'
                else: # cancel
                    state= 'state_abort'
                    break
                    
            elif (state=='state_create_seed'):
                needs_confirm= False
                MNEMONIC = Mnemonic(language="english")
                mnemonic = MNEMONIC.generate(strength=128)
                if MNEMONIC.check(mnemonic):    
                    (event, values)= self.request('create_seed', mnemonic)
                    if (event=='Next') and (values['use_passphrase'] is True):
                        use_passphrase= True
                        state= 'state_request_passphrase'
                    elif (event=='Next') and not values['use_passphrase']:
                        use_passphrase= False
                        if (needs_confirm):
                            state= 'state_confirm_seed'
                        else:
                            break
                    else: #Back
                        state= 'state_choose_seed_action'
                else:  #should not happen
                    #raise ValueError("Invalid BIP39 seed!")
                    logger.warning("Invalid BIP39 seed!")
                    self.request('show_error', "Invalid BIP39 seed!")
                    state= 'state_choose_seed_action'
                
            elif (state=='state_request_passphrase'):                        
                (event, values)= self.request('request_passphrase')
                if (event=='Next'):
                    passphrase= values['passphrase']
                    if (needs_confirm):
                        state= 'state_confirm_seed'
                    else:
                       break #finished
                else: #Back
                    state= 'state_choose_seed_action'
                
            elif (state=='state_confirm_seed'):               
                (event, values)= self.request('confirm_seed')
                mnemonic_confirm= values['seed_confirm']
                if (event=='Next') and (mnemonic== mnemonic_confirm):
                    if (use_passphrase):
                        state= 'state_confirm_passphrase'
                    else:
                        break #finish!
                elif (event=='Next') and (mnemonic!= mnemonic_confirm):
                    self.request('show_error','Seed mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
                    
            elif (state=='state_confirm_passphrase'):            
                (event, values)= self.request('confirm_passphrase')
                passphrase_confirm= values['passphrase_confirm']
                if (event=='Next') and (passphrase== passphrase_confirm):
                    break #finish!
                elif (event=='Next') and (passphrase!= passphrase_confirm):
                    self.request('show_error','Passphrase mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
            
            elif (state== 'state_restore_from_seed'):
                needs_confirm= False
                (event, values)= self.request('restore_from_seed')
                mnemonic= values['seed']
                use_passphrase= values['use_passphrase']
                if (event=='Next') and use_passphrase:
                    state= 'state_request_passphrase'
                elif (event=='Next') and not use_passphrase:
                    break #finished!
                else: #Back
                    state= 'state_choose_seed_action'
            
            else:
                logger.warning('State error!')
        
        # if mnemonic is None:
            # self.request('show_message', "Seed initialization aborted! \nYour Satochip may be unusable until a seed is created... \n Go to 'menu' -> 'Setup new Satochip' to complete setup")
        passphrase='' if passphrase is None else passphrase
        seed= Mnemonic.to_seed(mnemonic, passphrase) if mnemonic else None
        #print('mnemonic: '+ str(mnemonic))
        #print('passphrase: '+str(passphrase))
        #print('seed: '+str(seed.hex()))
        
        return (mnemonic, passphrase, seed, label, export_rights)

