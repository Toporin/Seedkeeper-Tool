import logging
import json
import hashlib
from os import urandom
# from queue import Queue #todo: remove
# import threading #todo:remove

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error, CardError, CardNotPresentError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION
from pysatochip.version import SEEDKEEPER_PROTOCOL_MAJOR_VERSION, SEEDKEEPER_PROTOCOL_MINOR_VERSION, SEEDKEEPER_PROTOCOL_VERSION

# print("DEBUG START client.py ")
# print("DEBUG START client.py __name__: "+__name__)
# print("DEBUG START client.py __package__: "+str(__package__))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
               
class Client:
    
    dic_type= {0x30:'BIP39 mnemonic', 0x40:'Electrum mnemonic', 0x10:'Masterseed', 0x70:'Public Key', 0x90:'Password', 0xA0:'Authentikey certificate', 0xB0:'2FA secret'}
            
    def __init__(self, cc, handler, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.handler = handler
        self.handler.client= self
        # self.queue_request= Queue()
        # self.queue_reply= Queue()
        self.cc= cc
        self.truststore={}
        self.card_event= False
        self.card_label= ''
           
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
    
    def card_verify_authenticity(self):
        logger.debug('In card_verify_authenticity')
        # try:
            # pubkey= self.cc.card_export_perso_pubkey()
            # logger.debug('Device pubkey: '+ bytes(pubkey).hex())
        # except CardException as ex:
            # msg= ''.join(["Unable to verify card: feature unsupported! \n", 
                                # "Authenticity validation is only available starting with Satochip v0.12 and higher"])
            # self.handler.show_error(msg)
            # break
        # except UnexpectedSW12Error as ex:
            # self.handler.show_error(str(ex))
            # break
        
        # get certificate from device
        cert_pem=txt_error=""
        try:
            cert_pem=self.cc.card_export_perso_certificate()
            logger.debug('Cert PEM: '+ str(cert_pem))
        except CardError as ex:
            txt_error= ''.join(["Unable to get device certificate: feature unsupported! \n", 
                                "Authenticity validation is only available starting with Satochip v0.12 and higher"])
        except CardNotPresentError as ex:
            txt_error= "No card found! Please insert card."
        except UnexpectedSW12Error as ex:
            txt_error= "Exception during device certificate export: " + str(ex)
        
        if cert_pem=="(empty)":
            txt_error= "Device certificate is empty: the card has not been personalized!"
        
        if txt_error!="":
            return False, "(empty)", "(empty)", "(empty)", txt_error
        
        # check the certificate chain from root CA to device
        from pysatochip.certificate_validator import CertificateValidator
        validator= CertificateValidator()
        is_valid_chain, device_pubkey, txt_ca, txt_subca, txt_device, txt_error= validator.validate_certificate_chain(cert_pem, self.cc.card_type)
        if not is_valid_chain:
            return False, txt_ca, txt_subca, txt_device, txt_error
        
        # perform challenge-response with the card to ensure that the key is correctly loaded in the device
        is_valid_chalresp, txt_error = self.cc.card_challenge_response_pki(device_pubkey)
       
        return is_valid_chalresp, txt_ca, txt_subca, txt_device, txt_error
    
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
            if (self.cc.card_type=='Satochip'):
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"Satochip version={v_applet} SeedKeeperTool supported version= {v_supported}")#debugSatochip
                if (v_applet<12): # v0.12 is the minimum version supported by SeedKeeperTool
                    msg=(('The version of your Satochip does not support SeedKeeperTool')+ '\n' 
                                + f'    Satochip version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Minimum supported version: 0.12')
                    self.request('show_error', msg)
                    #return False #?
                elif (v_supported<v_applet):
                    msg=(('The version of your Satochip is higher than supported by SeedKeeperTool. You should update SeedKeeperTool to ensure correct functioning!')+ '\n' 
                                + f'    Satochip version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {SATOCHIP_PROTOCOL_MAJOR_VERSION}.{SATOCHIP_PROTOCOL_MINOR_VERSION}')
                    self.request('show_error', msg)            
            elif (self.cc.card_type=='SeedKeeper'):
                v_supported= SEEDKEEPER_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"SeedKeeper version={v_applet} SeedKeeperTool supported version= {v_supported}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(('The version of your SeedKeeper is higher than supported by SeedKeeperTool. You should update SeedKeeperTool to ensure correct functioning!')+ '\n' 
                                + f'    SeedKeeper version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {SEEDKEEPER_PROTOCOL_MAJOR_VERSION}.{SEEDKEEPER_PROTOCOL_MINOR_VERSION}')
                    self.request('show_error', msg)
            
            if  (self.cc.setup_done):
                #v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
                # v_supported= SATOCHIP_PROTOCOL_VERSION 
                # v_applet= d["protocol_version"] 
                # logger.info(f"Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                # if (v_supported<v_applet):
                    # msg=(('The version of your Satochip is higher than supported by SeedKeeper. You should update SeedKeeper to ensure correct functioning!')+ '\n' 
                                # + f'    SeedKeeper version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                # + f'    Supported version: {SEEDKEEPER_PROTOCOL_MAJOR_VERSION}.{SEEDKEEPER_PROTOCOL_MINOR_VERSION}')
                    # self.request('show_error', msg)
                
                if (self.cc.needs_secure_channel):
                    self.cc.card_initiate_secure_channel() 
                
            # START setup device (done only once)
            else:
                #setup dialog
                (event, values)= self.handler.setup_card()
                if (event != 'Submit'):
                    logger.warning('Setup aborted: a PIN code is required to initialize the card!')
                    self.handler.show_error('A PIN code is required to initialize the card.\nInitialization aborted!')
                    return False
                pin_0= list(values['pin'].encode('utf8'))
                label = values['card_label']
                
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0= list(urandom(16)); 
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 32 #0x0000 # => for satochip - TODO: hardcode value?
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
                
                # set card label
                try:
                    (response, sw1, sw2)= self.cc.card_set_label(label)
                except Exception as ex:
                    logger.warning(f"Error while setting card label: {str(ex)}")
            # END setup device
            
            # verify pin:
            try: 
                self.cc.card_verify_PIN()
            except Exception as ex:
                logger.warning(repr(ex))
                self.request('show_error', repr(ex))
                return False
            
            # get authentikey
            try:
                self.authentikey=self.cc.card_export_authentikey()
            except Exception as ex:
                logger.warning(repr(ex))
                self.request('show_error', repr(ex))
                return False
            
            # TODO: option: get certificate & validation?
            # try:
                # self.certificate=self.cc.card_export_perso_certificate()
            # except Exception as ex:
                # self.certificate="(unsupported)"
            
            #card label 
            try:
                (response, sw1, sw2, card_label)= self.cc.card_get_label()
                self.card_label= card_label
            except Exception as ex:
                logger.warning(f"Error while getting card label: {str(ex)}")
            
            # add authentikey to TrustStore
            authentikey_hex= self.authentikey.get_public_key_bytes(compressed=False).hex()
            if authentikey_hex in self.truststore:
                pass #self.handler.show_success('Authentikey already in TrustStore!')
            else:
                authentikey_bytes= bytes.fromhex(authentikey_hex)
                secret= bytes([len(authentikey_bytes)]) + authentikey_bytes
                fingerprint= hashlib.sha256(secret).hexdigest()[0:8]
                authentikey_comp= self.authentikey.get_public_key_bytes(compressed=True).hex()
                self.truststore[authentikey_hex]= {'card_label':card_label, 'fingerprint':fingerprint, 'authentikey_comp':authentikey_comp}#self.card_label
                #self.show_success('Authentikey added to TrustStore!')
                self.handler.show_notification('Information: ', f'Authentikey added to TrustStore! \n{authentikey_comp}')
            
            # return true if wizard finishes correctly 
            return True
        
        # no card present 
        return False
        
    ############################
    #    Secret on-card generation 
    ############################  
    
    def generate_oncard(self):
        event, values = self.handler.generate_oncard_menu()
        if (event != 'Submit'):
            return None
        
        try: 
            stype= values['type'][0] # values['type']     
            if stype== 'Masterseed':
                self.generate_seed()
            elif stype== '2FA Secret':
                self.generate_2FA()
            else:
               #should not happen
                logger.error(f'In import_secret: wrong type for import: {stype}')
                return None
        except Exception as ex:
            logger.error(f"Error during secret on-card generation: {ex}")
            self.handler.show_error(f"Error during secret on-card generation: {ex}")
            return None 
                
    def generate_seed(self):
        event, values = self.handler.generate_new_seed()
        
        if event== 'Submit':
            logger.debug(values)
            label= values['label']
            export_rights= 0x01 if (values['export_rights']=='Export in plaintext allowed') else 0x02
            size= int(values['size'].split(' ')[0])
            
            (response, sw1, sw2, id, fingerprint)= self.cc.seedkeeper_generate_masterseed(size, export_rights, label)
            
            if (sw1==0x90 and sw2==0x00):
                self.handler.show_success(f'Masterseed generated with succes! \nId: {id} \nFingerprint: {fingerprint}')
            elif (sw1==0x9c and sw2==0x01):
                self.handler.show_error(f'Error during Masterseed generation: no memory available!')
            elif (sw1==0x9c and sw2==0x04):
                self.handler.show_error(f'Error during Masterseed generation: SeedKeeper is not initialized!')
            else:
                self.handler.show_error(f'Unknown error (error code {hex(256*sw1+sw2)})')
        else:
            #cancel or None
            return
    
    def generate_2FA(self):
        event, values = self.handler.generate_new_2FA_secret()
        
        if event== 'Submit':
            logger.debug(values)
            label= values['label']
            export_rights= 0x01 if (values['export_rights']=='Export in plaintext allowed') else 0x02
            
            (response, sw1, sw2, id, fingerprint)= self.cc.seedkeeper_generate_2FA_secret(export_rights, label)
            
            if (sw1==0x90 and sw2==0x00):
                self.handler.show_success(f'2FA secret generated with succes! \nId: {id} \nFingerprint: {fingerprint}')
            elif (sw1==0x9c and sw2==0x01):
                self.handler.show_error(f'Error during 2FA secret generation: no memory available!')
            elif (sw1==0x9c and sw2==0x04):
                self.handler.show_error(f'Error during 2FA secret generation: SeedKeeper is not initialized!')
            elif (sw1==0x6D and sw2==0x00):
                self.handler.show_error(f'Error during 2FA secret generation: operation not supported!')
            else:
                self.handler.show_error(f'Unknown error (error code {hex(256*sw1+sw2)})')
        else:
            #cancel or None
            return
    
    ############################
    #    Secret import 
    ############################  
    def import_secret(self):
        
        event, values = self.handler.import_secret_menu()
        if (event != 'Submit'):
            return None
            
        try: 
            stype= values['type'][0] # values['type']     
            if stype== 'Mnemonic phrase':
                event, values= self.handler.mnemonic_wizard(self.cc.card_type)
                if event != 'Submit':
                    self.handler.show_notification('Information: ', 'Operation cancelled by user')
                    return None
                
                if (self.cc.card_type=='SeedKeeper'):
                    mnemonic= values['mnemonic']
                    mnemonic_list= list(mnemonic.encode("utf-8"))
                    mnemonic_type= values['mnemonic_type']
                    passphrase= values['passphrase']
                    passphrase_list= list(passphrase.encode('utf-8'))
                    label= values['label']
                    export_rights= values['export_rights']
                    
                    stype= 'Electrum mnemonic' if mnemonic_type.startswith('Electrum') else 'BIP39 mnemonic' # 'BIP39 mnemonic' , 'Electrum mnemonic (segwit)', 'Electrum mnemonic (non-segwit)'
                    secret_list= [len(mnemonic_list)]+ mnemonic_list + [len(passphrase_list)] + passphrase_list
                    header= self.make_header(stype, export_rights, label)
                    secret_dic={'header':header, 'secret_list':secret_list}
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                    #self.handler.show_success(f"Secret successfully imported with id {sid}")
                    
                    # also import corresponding masterseed
                    masterseed_list= list( values['masterseed'] )
                    secret_list= [len(masterseed_list)] + masterseed_list
                    label= "Masterseed from mnemonic '" + values['label'] +"'"
                    header= self.make_header('Masterseed', export_rights, label)
                    secret_dic={'header':header, 'secret_list':secret_list}
                    (sid2, fingerprint2) = self.cc.seedkeeper_import_secret(secret_dic)
                    self.handler.show_success(f"Mnemonic successfully imported with id {sid} & fingerprint {fingerprint} \nMasterseed successfully imported with id {sid2} & fingerprint {fingerprint2}")
                    return 2
                else: #Satochip
                    mnemonic_type= values['mnemonic_type']
                    if mnemonic_type.startswith('Electrum'):
                        message= '  '.join([
                                    ("You are trying to import an Electrum mnemonic to a Satochip hardware wallet."),
                                    ("\nElectrum mnemonics are not compatible with the BIP39 mnemonics typically used in hardware wallets."), 
                                    ("\nThis means you may have difficulty to import this mnemonic in another wallet in the future."),
                                    ("\n\nAre you sure you want to continue? If you are not sure, click on 'no'. "),
                                ])
                        yes_no= self.handler.yes_no_question(message)
                        if not yes_no:
                            self.handler.show_notification('Information: ', 'Operation cancelled by user')
                            return 0
                    masterseed_list= list( values['masterseed'] )
                    authentikey= self.cc.card_bip32_import_seed(masterseed_list)
                    if authentikey==None:
                        raise Exception("Error during mnemonic import: maybe the Satochip is already seeded.")
                    self.handler.show_success(f"Mnemonic successfully imported to Satochip!")
                    return 1
                    
            elif stype== 'Masterseed':
                event, values= self.handler.import_secret_masterseed()
                if event != 'Submit':
                    self.handler.show_message(f"Operation cancelled")
                    return None
                masterseed= values['masterseed']
                masterseed_list= list( bytes.fromhex(masterseed) )
                if (self.cc.card_type=='SeedKeeper'):
                    secret_list= [len(masterseed_list)] + masterseed_list
                    label= values['label']
                    export_rights= values['export_rights']
                    header= self.make_header(stype, export_rights, label)
                    secret_dic={'header':header, 'secret_list':secret_list}
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                    self.handler.show_success(f"Masterseed successfully imported with id {sid} & fingerprint {fingerprint}")
                else: #Satochip
                    authentikey= self.cc.card_bip32_import_seed(masterseed_list)
                    self.handler.show_success(f"Masterseed successfully imported to Satochip!")
                return 1
                    
            elif stype== 'Secure import from json':
                self.import_secure_secret()
            
            elif stype== 'Trusted Pubkey' or stype=='Authentikey from TrustStore': #'Public Key':
                if stype=='Trusted Pubkey':
                    event, values= self.handler.import_secret_pubkey()
                    stype = 'Public Key' # Need to change stype to match the expected dict value
                else: # stype=='Authentikey from TrustStore'
                    if len(self.truststore)==0:
                        self.handler.show_message(f"No Authentikey found in TrustStore.\nOperation cancelled!")
                        return None
                    event, values= self.handler.import_secret_authentikey()
                
                if event != 'Submit':
                    self.handler.show_notification('Information: ', 'Operation cancelled by user')
                    return None

                authentikey= values['pubkey']
                authentikey_list= list( bytes.fromhex(authentikey) )
                if (self.cc.card_type=='SeedKeeper'):
                    secret_list= [len(authentikey_list)] + authentikey_list
                    label= values['label']
                    export_rights= values['export_rights']
                    header= self.make_header(stype, export_rights, label)
                    secret_dic={'header':header, 'secret_list':secret_list}
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                    self.handler.show_success(f"Authentikey {authentikey} imported with id {sid} & fingerprint {fingerprint}")
                    return sid
                else: #Satochip
                    pubkey_hex=  self.cc.card_import_trusted_pubkey(authentikey_list)
                    self.handler.show_success(f"Trusted pubkey '{pubkey_hex}' imported to Satochip!")
                    return 1
               
            elif stype== 'Password':
                event, values= self.handler.import_secret_password()
                if event == 'Submit':
                    password= values['password']
                    password_list= list( password.encode('utf-8') )
                    secret_list= [len(password_list)] + password_list
                    label= values['label']
                    export_rights= values['export_rights']
                    header= self.make_header(stype, export_rights, label)
                    secret_dic={'header':header, 'secret_list':secret_list}
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                    self.handler.show_success(f"Secret successfully imported with id {sid} & fingerprint {fingerprint}")
                    return 1
                else:
                    #self.handler.show_message(f"Operation cancelled by user") 
                    self.handler.show_notification('Information: ', 'Operation cancelled by user')
                    return None
                
            else:
                #should not happen
                logger.error(f'In import_secret: wrong type for import: {stype}')
                return None
        except Exception as ex:
            logger.error(f"Error during secret import: {ex}")
            self.handler.show_error(f"Error during secret import: {ex}")
            return None
          
    def import_secure_secret(self):
        logger.debug("In import_secure_secret()") #debugSatochip
        
        event, values = self.handler.import_secure_secret()
        
        if (event != 'Import'):
            return None   
                        
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
        authentikey= self.cc.card_export_authentikey().get_public_key_bytes(compressed=False).hex()
        if authentikey != authentikey_importer:
            self.handler.show_error(f'Authentikey mismatch: \n\tFrom json: {authentikey_importer[0:66]} \n\tFrom card: {authentikey[0:66]}')
            return None
        
        if (self.cc.card_type=='SeedKeeper'):
            # get sid from authentikey_exporter
            authentikey_exporter=secret_json['authentikey_exporter']
            sid_pubkey=None
            headers= self.cc.seedkeeper_list_secret_headers()
            for header_dic in headers:
                if header_dic['type']==0x70:
                    secret_dic= self.cc.seedkeeper_export_secret(header_dic['id'], None) #export pubkey in plain
                    pubkey= secret_dic['secret'][2:] # [0:2] is the pubkey size in hex
                    if pubkey== authentikey_exporter:
                        sid_pubkey= header_dic['id']
                        logger.debug('Found sid_pubkey: ' + str(sid_pubkey) )
                        break
            
            if sid_pubkey is None:
                #look in the truststore
                card_label= self.truststore.get(authentikey_exporter, {}).get('card_label', None) # self.truststore.get(authentikey_exporter, None)
                if card_label is not None:
                    authentikey_exporter_comp= self.truststore.get(authentikey_exporter, {}).get('authentikey_comp', None)
                    yes_no= self.handler.yes_no_question(f"The following authentikey has been found in the TrustStore: \n\tAuthentikey: {authentikey_exporter_comp} \n\tLabel: '{card_label}' \nContinue import with this authentikey?")
                    if yes_no:
                        pubkey_list= list( bytes.fromhex(authentikey_exporter) )
                        secret_list= [len(pubkey_list)] + pubkey_list
                        header= self.make_header('Authentikey from TrustStore', 'Export in plaintext allowed', card_label+' authentikey')
                        secret_dic={'header':header, 'secret_list':secret_list}
                        (sid_pubkey, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic)
                        self.handler.show_notification('Information: ', f"Authentikey '{card_label}' successfully imported with id {sid_pubkey}" )
                    else:
                        self.handler.show_notification('Information: ', 'Secure import cancelled by user')
                        return None
                else: # nothing in trustsore 
                    self.handler.show_error('Could not find a trusted pubkey matching '+ authentikey_exporter[:66])
                    return None
            
            nb_secrets=nb_errors=0
            msg=''
            for secret_dic in secret_json['secrets']:
                try:
                    (itype, stype, label, fingerprint_header)= self.parse_secret_header(secret_dic)
                    (sid, fingerprint) = self.cc.seedkeeper_import_secret(secret_dic, sid_pubkey)
                    nb_secrets+=1
                    msg+= f"Imported {stype} with label '{label}', fingerprint {fingerprint} & id {sid}\n" 
                except (SeedKeeperError, UnexpectedSW12Error) as ex:
                    nb_errors+=1
                    logger.error(f"Error during secure secret import: {ex}")
                    msg+= f'Error during secret import: {ex} \n'
            if (nb_errors==0):
                msg= f'Imported {nb_secrets} secrets successfully:\n' + msg
                self.handler.show_success(msg)
                return nb_secrets
            else:
                msg= f'Warning: {nb_errors} errors raised during secret import:\n' + msg
                self.handler.show_error(msg)
                return None
        
        else: # Satochip         
            # check if authentikey_exporter is trusted
            authentikey_exporter=secret_json['authentikey_exporter']
            pubkey_hex= self.cc.card_export_trusted_pubkey()
            if (pubkey_hex== authentikey_exporter): #ok, nothing to be done
                pass
            elif (pubkey_hex==65*'00'): # no trusted_key defined inside the Satochip
                #look in the truststore
                card_label= self.truststore.get(authentikey_exporter, {}).get('card_label', None) # self.truststore.get(authentikey_exporter, None)
                if card_label is not None:
                    authentikey_exporter_comp= self.truststore.get(authentikey_exporter, {}).get('authentikey_comp', None)
                    yes_no= self.handler.yes_no_question(f"The following authentikey has been found in the TrustStore: \n\tAuthentikey: {authentikey_exporter_comp} \n\tLabel: '{card_label}' \nContinue import with this authentikey?")
                    if yes_no:
                        authentikey_list= list(bytes.fromhex(authentikey_exporter))
                        pubkey_hex=  self.cc.card_import_trusted_pubkey(authentikey_list)
                        self.handler.show_notification('Information: ', f"Authentikey '{card_label}' successfully imported to Satochip!")
                    else:
                        self.handler.show_notification('Information: ', 'Secure import cancelled by user')
                        return None
                else: # nothing found in trustsore 
                    self.handler.show_error('Import aborted: could not find a trusted pubkey matching '+ authentikey_exporter[:66])
                    return None
            elif (pubkey_hex==65*'FF'): # unsupported
                self.handler.show_error(f'Import aborted: this version of Satochip does not support secure import from a SeedKeeper!')
                return None
            else: 
                self.handler.show_error(f'Import aborted: the authentikey_exporter {authentikey_exporter[:66]} does not match the Satochip trusted_pubkey {pubkey_hex[:66]}!')
                return None
            
            # select Masterseed/2FA from list (if any)
            index_list=[]
            masterseed_list=[]
            secret_list=[]
            for index, secret_dic in enumerate(secret_json['secrets']):
                (itype, stype, label, fingerprint)= self.parse_secret_header(secret_dic)
                if (itype==0x10):
                    index_list.append(index)
                    secret_list.append('Masterseed: ' + fingerprint + ': ' + label)
                elif (itype==0xB0):
                    index_list.append(index)
                    secret_list.append('2FA secret: ' + fingerprint + ': ' + label)
                else:
                    continue
            if ( len(index_list)==0 ):
                self.handler.show_error(f'Import aborted: no Masterseed or 2FA found in json!')
                return None
            else:
                event2, values2 = self.handler.choose_secret_from_list(secret_list)
                if event2=='Submit':
                    index= index_list[ secret_list.index(values2['secret_list'][0]) ] #values2['secret_list'] is a list
                else:
                    self.handler.show_notification('Information: ', 'Secure import cancelled by user')
                    return None
                
            # do the import
            secret_dic= secret_json['secrets'][index] 
            (itype, stype, label, fingerprint)= self.parse_secret_header(secret_dic)
            try:
                if itype==0x10: #masterseed
                    authentikey = self.cc.card_import_encrypted_secret(secret_dic)
                    authentikey_hex= authentikey.get_public_key_bytes(compressed=True).hex()
                    self.handler.show_success(f'Successfully imported masterseed to Satochip with authentikey: {authentikey_hex}')
                    return 1
                elif itype==0xB0: #2FA
                    self.cc.card_import_encrypted_secret(secret_dic)
                    self.handler.show_success(f'Successfully imported 2FA with fingerprint {fingerprint} to Satochip!')
                    return 1
            except Exception as ex:
                self.handler.show_error(str(ex))
                return None
    
    ############################
    #    Utils
    ############################  
    
    def  get_secret_header_list(self):
        # get a list of all the secrets & pubkeys available
        #dic_type= {0x30:'BIP39 mnemonic', 0x40:'Electrum mnemonic', 0x10:'Masterseed', 0x70:'Public Key', 0x90:'Password'}
        label_list=[]
        id_list=[]
        label_pubkey_list=['None (export to plaintext)']
        id_pubkey_list=[None]
        fingerprint_pubkey_list=[]
        try:
            headers= self.cc.seedkeeper_list_secret_headers()
            for header_dic in headers:
                label_list.append( Client.dic_type.get(header_dic['type'], hex(header_dic['type'])) + ': ' + header_dic['fingerprint'] + ': '  + header_dic['label'] )
                id_list.append( header_dic['id'] )
                if header_dic['type']==0x70:
                    pubkey_dic= self.cc.seedkeeper_export_secret(header_dic['id'], None) #export pubkey in plain #todo: compressed form?
                    pubkey= pubkey_dic['secret'][2:10] # [0:2] is the pubkey size in hex
                    label_pubkey_list.append('In SeedKeeper: ' + header_dic['fingerprint'] + ': '  + header_dic['label'] + ': ' + pubkey + '...')
                    id_pubkey_list.append( header_dic['id'] )
                    fingerprint_pubkey_list.append(header_dic['fingerprint'])
        except Exception as ex:      
            logger.error(f"Error during secret header listing: {ex}")
            #self.show_error(f'Error during secret export: {ex}')
            #return None
        
        # add authentikeys from Truststore
        label_authentikey_list, authentikey_list= self.get_truststore_list(fingerprint_pubkey_list)
        label_pubkey_list.extend(label_authentikey_list)
        id_pubkey_list.extend(authentikey_list)
         
        return label_list, id_list, label_pubkey_list, id_pubkey_list
    
    def get_truststore_list(self, fingerprint_list=[]):
        # get list of authentikeys from TrustStore, whose fingerprint is not already in fingerprint_list
        label_authentikey_list=[]
        authentikey_list=[]
        for authentikey, dic_info in self.truststore.items():
            if authentikey== self.cc.parser.authentikey.get_public_key_bytes(False).hex(): # self.authentikey.get_public_key_bytes(False).hex(): 
                continue #skip own authentikey
            card_label= dic_info['card_label']
            fingerprint= dic_info['fingerprint']
            authentikey_comp= dic_info['authentikey_comp']
            if fingerprint not in fingerprint_list: #skip authentikey already in device
                keyvalue = 'In Truststore: ' + fingerprint + ': ' + card_label + ' authentikey' +": "+ authentikey_comp[0:8] + "..."
                label_authentikey_list.append(keyvalue)
                authentikey_list.append(authentikey)
               
        return label_authentikey_list, authentikey_list
    
    #TODO: use pysatochip.cardConnector.make_header()
    def make_header(self, stype, export_rights, label):
        dic_type= {'BIP39 mnemonic':0x30, 'Electrum mnemonic':0x40, 'Masterseed':0x10, 'Secure import from json':0x00, 
                                'Public Key':0x70, 'Authentikey from TrustStore':0x70, 'Password':0x90, 'Authentikey certificate':0xA0, '2FA secret':0xB0}
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
        
    def parse_secret_header(self, secret_dic):
        header_list= list(bytes.fromhex(secret_dic['header']))[2:] #first 2 bytes is sid
        itype= header_list[0]
        stype= Client.dic_type.get(itype, hex(itype))
        label_size= header_list[12]
        try:
            #if ( len(header_list)>=(12+label_size) ):
            label= header_list[13:(13+label_size)]
            label= bytes(label).decode('utf8')
        except Exception as ex:
            label= 'label error'
        fingerprint= bytes(header_list[6:(6+4)]).hex()

        return itype, stype, label, fingerprint
    