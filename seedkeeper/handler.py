#import PySimpleGUI as sg   
#import PySimpleGUIWx as sg 
import PySimpleGUIQt as sg 
import base64    
import json
import getpass
import pyperclip
from pyperclip import PyperclipException
import sys
import os
import logging
from queue import Queue 

from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.CardConnector import CardConnector
from pysatochip.CardConnector import UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION
from pysatochip.version import SEEDKEEPER_PROTOCOL_MAJOR_VERSION, SEEDKEEPER_PROTOCOL_MINOR_VERSION, SEEDKEEPER_PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
  
class HandlerTxt:
    def __init__(self):
        pass

    def update_status(self, isConnected):
        if (isConnected):
            print("Card connected!")
            self.client.new_card_present=True
        else:
            print("Card disconnected!")

    def show_error(self,msg):
        print("ERROR:" + msg)
    
    def show_success(self, msg):
        print(msg)
        
    def show_message(self, msg):
        print(msg)
    
    def yes_no_question(self, question):
        while "the answer is invalid":
            reply = str(input(question+' (y/n): ')).lower().strip()
            if reply[0] == 'y':
                return True
            if reply[0] == 'n':
                return False
        
    def get_passphrase(self, msg): 
        is_PIN=True
        pin = getpass.getpass(msg) #getpass returns a string
        return (is_PIN, pin)
        
    def QRDialog(self, data, parent=None, title = '', show_text=False, msg= ''):
        print(msg)

class HandlerSimpleGUI:
    def __init__(self, loglevel= logging.WARNING): 
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        sg.theme('BluePurple')
        # absolute path to python package folder of satochip_bridge ("lib")
        #self.pkg_dir = os.path.split(os.path.realpath(__file__))[0] # does not work with packaged .exe 
        if getattr( sys, 'frozen', False ):
            # running in a bundle
            self.pkg_dir= sys._MEIPASS # for pyinstaller
        else :
            # running live
            self.pkg_dir = os.path.split(os.path.realpath(__file__))[0]
        logger.debug("PKGDIR= " + str(self.pkg_dir))
        self.satochip_icon= self.icon_path("satochip.png") #"satochip.png"
        self.satochip_unpaired_icon= self.icon_path("satochip_unpaired.png") #"satochip_unpaired.png"
         
    def icon_path(self, icon_basename):
        #return resource_path(icon_basename)
        return os.path.join(self.pkg_dir, icon_basename)
    
    def update_status(self, isConnected):
        logger.debug('In update_status')
        if (isConnected):
            self.client.new_card_present=True
            #self.client.card_init_connect() # NOK: cannot create pySimpleGui object from thread 
            #self.tray.update(filename=self.satochip_icon) #self.tray.update(filename=r'satochip.png')
        else:
            #self.tray.update(filename=self.satochip_unpaired_icon) #self.tray.update(filename=r'satochip_unpaired.png')
            pass
        logger.debug('End update_status')
        
         
    def show_error(self, msg):
        sg.popup('Error!', msg, icon=self.satochip_unpaired_icon)
    def show_success(self, msg):
        sg.popup('Success!', msg, icon=self.satochip_icon)
    def show_message(self, msg):
        sg.popup('Notification', msg, icon=self.satochip_icon)
    def show_notification(self,msg):
        #logger.debug("START show_notification")
        #self.tray.ShowMessage("Notification", msg, filename=self.satochip_icon, time=10000) #old
        #self.tray.ShowMessage("Notification", msg, messageicon=sg.SYSTEM_TRAY_MESSAGE_ICON_INFORMATION, time=100000)
        #logger.debug("END show_notification")
        pass
    
    def approve_action(self, question):
        logger.debug('In approve_action')
        layout = [[sg.Text(question)],    
                        [sg.Checkbox('Skip confirmation for this connection (not recommended)', key='skip_conf')], 
                        [sg.Button('Yes'), sg.Button('No')]]   
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return (event, values)
        
    def yes_no_question(self, question):
        logger.debug('In yes_no_question')
        layout = [[sg.Text(question)],      
                        [sg.Button('Yes'), sg.Button('No')]]      
        #window = sg.Window('Confirmation required', layout, icon=SatochipBase64)    #NOK
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        #window = sg.Window('Confirmation required', layout, icon="satochip.ico")    #ok
        event, values = window.read()    
        window.close()  
        del window
        
        #logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        if event=='Yes':
            return True
        else: # 'No' or None
            return False
                
    def get_passphrase(self, msg): 
        logger.debug('In get_passphrase')
        layout = [[sg.Text(msg)],      
                         [sg.InputText(password_char='*', key='pin')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('PIN required', layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        is_PIN= True if event=='Submit' else False 
        pin = values['pin']
        # logger.debug("Type of pin from getpass:"+str(type(pin)))
        # logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        return (is_PIN, pin)
    
    def get_data(self, msg): 
        logger.debug('In get_data')
        layout = [[sg.Text(msg)],      
                         [sg.InputText(key='data')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('SeedKeeper', layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        is_data= True if event=='Submit' else False 
        data = values['data']
        return (is_data, data)
     

    
####################################
#            SEEDKEEPER                               
####################################

    def main_menu(self):
        logger.debug('In main_menu')
        layout = [[sg.Text('Welcome to SeedKeeper Utility !')],      
                        [sg.Button('Generate a new seed')],
                        [sg.Button('Import a Secret')],
                        [sg.Button('Export a Secret')],
                        [sg.Button('Make a backup')],
                        [sg.Button('List Secrets')],
                        [sg.Button('Get logs')],
                        [sg.Button('About')],
                        [sg.Button('Quit')],
                    ]      
        window = sg.Window('SeedKeeper utility', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        return event
        
    def generate_new_seed(self):
        logger.debug('In generate_new_seed')
        layout = [
            [sg.Text('Please enter seed settings below: ')],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(20, 1))],
            [sg.Text('Size: ', size=(10, 1)), sg.InputCombo(('16 bytes' , '32 bytes', '48 bytes', '64 bytes'), key='size', size=(20, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in clear allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ]   
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok

        event, values = window.read()    
        window.close()  
        del window
        
        logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        logger.debug("Type of values from getpass:"+str(type(values))+str(values))
        return event, values
        
    def import_secret_menu(self):
        logger.debug('In import_secret_menu')
        
        import_list= ['BIP39 seed', 'Electrum seed', 'MasterSeed', 'Secure import from json', 'Public Key', 'Authentikey from TrustStore', 'Password']
        
        layout = [
            [sg.Text('Choose the type of secret you wish to import: ', size=(30, 1))],
            #[sg.Text('Type: ', size=(10, 1)), sg.InputCombo( import_list, key='type', size=(20, 1))],
            [sg.Listbox( import_list, key='type', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, size=(30, 7))],
            [sg.Submit(), sg.Cancel()]
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 1', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        return event, values
        
    def import_secret_masterseed(self):    
        logger.debug("import_secret_masterseed")
        
        layout = [
            [sg.Text('Enter the masterseed as a hex string with 32, 64, 96 or 128 characters: ', size=(40, 1))],
            [sg.Text('Hex value: ', size=(10, 1)), sg.InputText(key='masterseed', size=(40, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        #event, values=None, None
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    masterseed= values['masterseed']
                    int(masterseed, 16) # check if correct hex
                    masterseed= masterseed[masterseed.startswith("0x") and len("0x"):] #strip '0x' if need be
                    if len(masterseed) not in [32, 64, 96, 128]:
                        raise ValueError(f"Wrong seed length: {len(masterseed)}")
                    values['masterseed']= masterseed
                    #todo: limit label size to 127 max
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
                
        window.close()
        del window
        return event, values
    
    def import_secure_secret(self):
        logger.debug('In import_secure_secret')
        layout = [
            [sg.Text('Enter json import text in the box below:')],
            [sg.Multiline(key='json', size=(60, 4) )],
            [sg.Button('Import', bind_return_key=True), sg.Cancel()]
        ]   
        window = sg.Window('SeedKeeper: import secure secret', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return event, values
        
    def import_secret_pubkey(self):    
        logger.debug("import_secret_pubkey")
        layout = [
            [sg.Text('Enter the pubkey as a hex string: ', size=(40, 1))],
            [sg.Text('Hex value: ', size=(10, 1)), sg.InputText(key='pubkey', size=(68, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Text(size=(64,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        #event, values=None, None
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    pubkey= values['pubkey']
                    int(pubkey, 16) # check if correct hex
                    pubkey= pubkey[pubkey.startswith("0x") and len("0x"):] #strip '0x' if need be
                    
                    if len(pubkey) not in [66, 130]:
                        raise ValueError(f"Wrong pubkey length: {len(pubkey)} (should be 66 or 130 hex characters)")
                    elif len(pubkey)== 130 and not pubkey.startswith("04"):
                        raise ValueError(f"Wrong pubkey: uncompressed pubkey should start with '04' ")
                    elif len(pubkey)== 66 and not ( pubkey.startswith("02") or pubkey.startswith("03") ):
                        raise ValueError(f"Wrong pubkey: compressed pubkey should start with '02' or '03' ")
                        
                    if len(pubkey)==66: #compressed pubkey
                        #window['-OUTPUT-'].update('WARNING: compressed pubkeys have only limited support')
                        proceed= self.yes_no_question('WARNING: compressed pubkeys have only limited support.\nAre you sure you want to proceed?')
                        if not proceed:
                            continue
                            
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
                
        window.close()
        del window
        return event, values
    
    def import_secret_authentikey(self):
        logger.debug("import_secret_authentikey")
        
        list_from_dic=[]
        list_authentikey=[]
        #list_card_label=[]
        for authentikey, card_label in self.client.truststore.items():
            keyvalue = card_label +" - "+ authentikey[0:8] + "..." + authentikey[-8:]
            list_from_dic.append(keyvalue)
            list_authentikey.append(authentikey)
            #list_card_label.append(card_label)
        
        layout = [
            [sg.Text('Choose the authentikey you wish to import from TrustStore: ', size=(60, 1))],
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(list_from_dic, key='authentikey', size=(40, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        values['authentikey']= list_authentikey[list_from_dic.index(values['authentikey'])] 
        #values['card_label']= list_card_label[list_authentikey.index(values['authentikey'])] 
        return event, values
    
    def import_secret_password(self):    
        logger.debug("import_secret_password")
        
        layout = [
            [sg.Text('Enter the password: ', size=(40, 1))],
            [sg.Text('Password: ', size=(10, 1)), sg.InputText(key='password', size=(30, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return event, values
            
    def export_secret(self):
        logger.debug('In export_secret')
        
        # get a list of all the secrets & pubkeys available
        (label_list, id_list, label_pubkey_list, id_pubkey_list)= self.client.get_secret_header_list()
        
        layout = [
            [sg.Text('Secret to export: ', size=(10, 1)), sg.InputCombo(label_list, key='label_list', size=(40, 1)) ], 
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(label_pubkey_list, key='label_pubkey_list', size=(40, 1)) ],
            [sg.Text('Label: ', size=(10, 1)), sg.Text(key='label')],
            [sg.Text('Fingerprint: ', size=(10, 1)), sg.Text(key='fingerprint')],
            [sg.Text('Type: ', size=(10, 1)), sg.Text(key='type')],
            [sg.Text('Origin: ', size=(10, 1)), sg.Text(key='origin')],
            [sg.Multiline(key='secret', size=(60, 4) )],
            [sg.Button('Export', bind_return_key=True), sg.Cancel()]
        ]   
        
        window = sg.Window('SeedKeeper export', layout)      
        while True:      
            event, values = window.read()      
            logger.debug(f"event: {event}")
            if event == 'Export':  #if event != 'Exit'  and event != 'Cancel':      
                try:     
                    label= values['label_list']
                    sid= id_list[ label_list.index(label) ]
                    label_pubkey= values['label_pubkey_list']
                    sid_pubkey= id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]
                except Exception as ex:      
                    self.show_error(f'Error during secret export: {ex}')
                    continue
                    
                try: 
                    secret_dict= self.client.cc.seedkeeper_export_secret(sid, sid_pubkey)
                    window['fingerprint'].update(secret_dict['fingerprint'])      
                    window['label'].update(secret_dict['label'])      
                    if secret_dict['origin']==0x01:
                        window['origin'].update('Plain import')      
                    elif secret_dict['origin']==0x02:
                        window['origin'].update('Secure import')   
                    elif secret_dict['origin']==0x03:
                        window['origin'].update('Generated on card')   
                    else:
                        window['origin'].update('Unknown')   
                    #TODO: parse secret depending to type for all cases (in CardDataParser?)
                    secret_list= secret_dict['secret']
                    
                    #plain export
                    if sid_pubkey is None: 
                        secret_size= secret_list[0]
                        secret_raw= secret_list[1:1+secret_size]
                        if (secret_dict['type']== 0x10): #Masterseed
                            secret= bytes(secret_raw).hex()
                            window['type'].update('Masterseed')      
                            #window['secret_field'].update('Masterseed: ')    
                            window['secret'].update(secret)    
                        elif (secret_dict['type']== 0x30): #BIP39
                            secret1= bytes(secret_raw).decode('utf-8')
                            secret= "BIP39: " + secret1
                            if len(secret_list)>=(2+secret_size): #passphrase
                                secret_size2= secret_list[1+secret_size]
                                secret_raw2= secret_list[2+secret_size:2+secret_size+secret_size2]
                                secret2= bytes(secret_raw2).decode('utf-8')
                                if len(secret2)>0:
                                    secret+= "\n" + "Passphrase: " + secret2
                            window['type'].update('BIP39') 
                            #window['secret_field'].update('BIP39: ')    
                            window['secret'].update(secret)    
                            #window['option_field'].update('Passphrase: ')    
                            #window['secret2'].update(secret2)    
                        elif (secret_dict['type']== 0x70): #pubkey
                            secret= bytes(secret_raw).hex()
                            window['type'].update('Pubkey') 
                            #window['secret_field'].update('Pubkey: ')    
                            window['secret'].update(secret)    
                        elif (secret_dict['type']== 0x90): #password
                            secret= bytes(secret_raw).decode('utf-8')
                            window['type'].update('Password') 
                            window['secret'].update(secret)   
                            #window['secret_field'].update('Password: ')    
                        else:
                            secret= "Raw hex: "+secret_dict['secret_hex']
                            #window['secret_field'].update('Secret: ')    
                            window['type'].update('Unknown') 
                            window['secret'].update(secret) 
                    
                    # secure export print json of Secret?
                    else: 
                        window['type'].update('Encrypted Secret') 
                        #window['fingerprint'].update('N/A (encrypted)')      
                        try:
                            #secret_dict_pubkey= self.client.cc.seedkeeper_export_plain_secret(sid_pubkey)
                            secret_dict_pubkey= self.client.cc.seedkeeper_export_secret(sid_pubkey)
                            authentikey_importer= secret_dict_pubkey['secret_hex'][2:]
                        except Exception as ex:
                            logger.warning('Exception during pubkey export: '+str(ex))
                            authentikey_importer= "(unknown)"
                        
                        secret_obj= {  
                                            'authentikey_exporter': self.client.cc.parser.authentikey.get_public_key_bytes(False).hex(),
                                            'authentikey_importer': authentikey_importer,
                                            'secrets':   [{
                                                    'label': secret_dict['label'], 
                                                    'type': secret_dict['type'],    
                                                    'origin': secret_dict['origin'], 
                                                    'export_rights': secret_dict['export_rights'], 
                                                    'rfu1': secret_dict['rfu1'], 
                                                    'rfu2': secret_dict['rfu2'], 
                                                    'fingerprint': secret_dict['fingerprint'], 
                                                    'header': bytes(secret_dict['header']).hex(), 
                                                    'iv': bytes(secret_dict['iv']).hex(), 
                                                    'secret_encrypted': bytes(secret_list).hex(),  #'secret_base64':base64.encodebytes( bytes(secret_list) ).decode('utf8'), #todo: in hex?
                                                    'hmac': bytes(secret_dict['hmac']).hex(), 
                                                }],
                                            }
                        secret= json.dumps(secret_obj)
                        window['secret'].update(secret)   
                        
                        
                except (SeedKeeperError, UnexpectedSW12Error) as ex:
                    #window['secret_field'].update('Secret: ')    
                    window['secret'].update(str(ex))      
                    window['type'].update("N/A")      
                    window['fingerprint'].update("N/A")      
                    window['label'].update("N/A")    
                    window['origin'].update("N/A")   
                
            else:      
                break      
            
        window.close()  
        del window
    
    def make_backup(self):
        logger.debug('In backup_menu')
        
        (label_list, id_list, label_pubkey_list, id_pubkey_list)= self.client.get_secret_header_list()
        label_pubkey_list=label_pubkey_list[1:] # remove (none) value and id
        id_pubkey_list=id_pubkey_list[1:]
        
        layout = [
            #[sg.Text('Secrets to export: ', size=(10, 1)), sg.InputCombo(type_list, key='type_list', size=(40, 1)) ], 
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(label_pubkey_list, key='label_pubkey_list', size=(40, 1)) ],
            [sg.Multiline(key='secret', size=(60, 8) )],
            [sg.Text('Number of secrets exported: ', size=(20, 1)), sg.Text(key='nb_secrets'), 
                sg.Text('Number of errors: ', size=(20, 1), visible=False), sg.Text(key='nb_errors', visible=False)],
            [sg.Button('Backup', bind_return_key=True), sg.Cancel()]
        ]   
        
        window = sg.Window('SeedKeeper backup', layout)     
        
        while True:      
            event, values = window.read()      
            logger.debug(f"event: {event}")
            if event == 'Backup':  #if event != 'Exit'  and event != 'Cancel':      
                
                #get trusted authentikey in plain
                try:
                    label_pubkey= values['label_pubkey_list']
                    sid_pubkey= id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]
                    secret_dict_pubkey= self.client.cc.seedkeeper_export_secret(sid_pubkey)
                    authentikey_importer= secret_dict_pubkey['secret_hex'][2:]
                except Exception as ex:
                    logger.warning('Exception during pubkey export: '+str(ex))
                    authentikey_importer= "(unknown)"
                
                # secret exported as json
                secrets_obj= {  
                        'authentikey_exporter': self.client.cc.parser.authentikey.get_public_key_bytes(False).hex(),
                        'authentikey_importer': authentikey_importer,
                        'secrets': []
                }
                
                # for all secret:
                nb_secrets=0
                nb_errors=0
                for sid in id_list:
                    if sid==sid_pubkey:
                        continue
                    try: 
                        secret_dict= self.client.cc.seedkeeper_export_secret(sid, sid_pubkey)
                        secret_list= secret_dict['secret']
                        secret= {  
                                        'label': secret_dict['label'], 
                                        'type': secret_dict['type'],    
                                        'fingerprint': secret_dict['fingerprint'], 
                                        'header': bytes(secret_dict['header']).hex(), 
                                        'iv': bytes(secret_dict['iv']).hex(), 
                                        'secret_encrypted': bytes(secret_list).hex(), 
                                        'hmac': bytes(secret_dict['hmac']).hex(), 
                                    }
                        secrets_obj['secrets'].append(secret)
                        nb_secrets+=1
                        window['nb_secrets'].update(nb_secrets)   
                    except (SeedKeeperError, UnexpectedSW12Error) as ex:
                        secret= {  'error': str(ex) }
                        secrets_obj['secrets'].append(secret)
                        nb_errors+=1
                        window['nb_errors'].update(nb_errors, visible=True) 
                        
                backup= json.dumps(secrets_obj)
                window['secret'].update(backup)   
                
            else:      
                break      
            
        window.close()  
        del window
                
        return backup
    
    def logs_menu(self):
        logger.debug('In logs_menu')
        ins_dic={0x40:'Create PIN', 0x42:'Verify PIN', 0x44:'Change PIN', 0x46:'Unblock PIN', 
                        0xA0:'Generate masterseed', 0xA5:'Reset secret',
                        0xA1:'Import secret', 0xA1A:'Import plain secret', 0xA1B:'Import encrypted secret', 
                        0xA2:'Export secret', 0xA2A:'Export plain secret', 0xA2B:'Export encrypted secret'}
        res_dic={0x9000:'OK', 0x63C0:'PIN failed', 0x9C03:'Operation not allowed', 0x9C04:'Setup not done', 0x9C05:'Feature unsupported', 
                        0x9C01:'No memory left', 0x9C08:'Secret not found', 0x9C10:'Incorrect P1', 0x9C11:'Incorrect P2', 0x9C0F:'Invalid parameter',
                        0x9C0B:'Invalid signature', 0x9C0C:'Identity blocked', 0x9CFF:'Internal error', 0x9C30:'Lock error', 0x9C31:'Export not allowed',
                        0x9C32:'Import data too long', 0x9C33:'Wrong MAC during import'}                
        
        try:
            (logs, nbtotal_logs, nbavail_logs)= self.client.cc.seedkeeper_print_logs(print_all=True)
        except Exception as ex:      
            self.show_error(f'Error during logs export: {ex}')
            return
            
        headings=['Operation', 'ID1', 'ID2', 'Result']
        logs= logs[0:nbtotal_logs]
        strlogs=[]
        # convert raw logs to readable data
        for log in logs:
            ins= log[0]
            id1= log[1]
            id2= log[2]
            result= log[3]
            if ins==0xA1: # encrypted or plain import? depends on value of id2
                ins= 0xA1A if (id2==0xFFFF) else 0xA1B
            elif ins==0xA2:
                ins= 0xA2A if (id2==0xFFFF) else 0xA2B
            ins= ins_dic.get( ins, hex(log[0]) ) 
            
            id1= 'N/A' if id1==0xFFFF else str(id1)
            id2= 'N/A' if id2==0xFFFF else str(id2)
            
            if (result & 0x63C0)== 0x63C0: # last nible contains number of pin remaining
                remaining_tries= (result & 0x000F)
                result= 'PIN failed - '+  str(remaining_tries) + ' tries remaining'
            else:
                result= res_dic.get( log[3], hex(log[3]) )
            
            strlogs.append([ins, id1, id2, result])
        
        txt1= f'Number of events recorded: {nbtotal_logs} out of {nbavail_logs} available'
        layout = [
                      [sg.Text(txt1, size=(60,1))],
                      [sg.Table(strlogs, headings=headings)],
                      [sg.Button('Ok')],
                    ]
        window = sg.Window('SeedKeeperUtil Logs', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window        
        
    def list_headers(self):
        logger.debug('In list_headers')
        
        try:
            headers =self.client.cc.seedkeeper_list_secret_headers()
        except Exception as ex:      
            self.show_error(f'Error during header listing: {ex}')
            return
            
        #TODO: nice presentation instead of raw data
        txt= f'Number of secrets stored: {len(headers)}'
        headings=['Id', 'Label', 'Type', 'Origin', 'Export rights', 'Nb plain exports', 'Nb encrypted exports', 'Nb secret exported', 'Fingerprint']
        dic_type= {0x30:'BIP39 seed', 0x40:'Electrum seed', 0x10:'MasterSeed', 0x70:'Public Key', 0x90:'Password'}
        dic_origin= {0x01:'Plaintext import', 0x02:'Encrypted import', 0x03:'Generated on card'}
        dic_export_rights={0x01:'Plaintext export allowed', 0x02:'Encrypted export only', 0x03:'Export forbidden'}
        
        strheaders=[]
        for header in headers:
            sid= str(header['id'])
            label= header['label']
            stype= dic_type.get( header['type'], hex(header['type']) ) #hex(header['type'])
            origin= dic_origin.get( header['origin'], hex(header['origin']) ) #hex(header['origin'])
            export_rights= dic_export_rights.get( header['export_rights'], hex(header['export_rights']) ) #str(header['export_rights'])
            export_nbplain= str(header['export_nbplain'])
            export_nbsecure= str(header['export_nbsecure'])
            export_nbcounter= str(header['export_counter']) if header['type']==0x70 else 'N/A'
            fingerprint= header['fingerprint']
            
            strheaders.append([sid, label, stype, origin, export_rights, export_nbplain, export_nbsecure, export_nbcounter, fingerprint])
            
         
        layout = [
                      [sg.Text(txt, size=(60,1))],
                      [sg.Table(strheaders, headings=headings, display_row_numbers=False)],
                      [sg.Button('Ok')],
                    ]
        window = sg.Window('SeedKeeperUtil Logs', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window      
       
    
    def about_menu(self):
        logger.debug('In about_menu')
        msg_copyright= ''.join([ '(c)2020 - Satochip by Toporin - https://github.com/Toporin/ \n',
                                                        "This program is licensed under the GNU Lesser General Public License v3.0 \n",
                                                        "This software is provided 'as-is', without any express or implied warranty.\n",
                                                        "In no event will the authors be held liable for any damages arising from \n"
                                                        "the use of this software."])
        #sw version
        # v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
        # sw_rel= str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION) +'.'+ str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION)
        v_supported= (SEEDKEEPER_PROTOCOL_MAJOR_VERSION<<8)+SEEDKEEPER_PROTOCOL_MINOR_VERSION
        sw_rel= str(SEEDKEEPER_PROTOCOL_MAJOR_VERSION) +'.'+ str(SEEDKEEPER_PROTOCOL_MINOR_VERSION)
        fw_rel= "N/A"
        is_seeded= "N/A"
        needs_2FA= "N/A"
        needs_SC= "N/A"
        authentikey= None
        authentikey_comp= "N/A"
        card_label= "N/A"
        msg_status= ("Card is not initialized! \nClick on 'Setup new Satochip' in the menu to start configuration.")
            
        (response, sw1, sw2, status)=self.client.cc.card_get_status()
        if (sw1==0x90 and sw2==0x00):
            #hw version
            v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
            fw_rel= str(status["protocol_major_version"]) +'.'+ str(status["protocol_minor_version"])  +' - '+ str(status["applet_major_version"]) +'.'+ str(status["applet_minor_version"])
            # status
            if (v_supported<v_applet):
                msg_status=(f'The version of your {self.client.cc.card_type}  is higher than supported. \nYou should update SeedKeeperUtil!')
            else:
                msg_status= 'SeedKeeperUtil is up-to-date'
            # needs2FA?
            if len(response)>=9 and response[8]==0X01: 
                needs_2FA= "yes"
            elif len(response)>=9 and response[8]==0X00: 
                needs_2FA= "no"
            else:
                needs_2FA= "unknown"
            #is_seeded?
            if len(response) >=10:
                is_seeded="yes" if status["is_seeded"] else "no" 
            else: #for earlier versions
                try: 
                    self.client.cc.card_bip32_get_authentikey()
                    is_seeded="yes"
                except UninitializedSeedError:
                    is_seeded="no"
                except Exception:
                    is_seeded="unknown"    
            # secure channel
            if status["needs_secure_channel"]:
                needs_SC= "yes"
            else:
                needs_SC= "no"
            # authentikey
            try:
                authentikey_pubkey=self.client.authentikey #self.client.cc.card_bip32_get_authentikey()
                authentikey_bytes= authentikey_pubkey.get_public_key_bytes(compressed=False)
                authentikey= authentikey_bytes.hex()
                authentikey_comp= authentikey_pubkey.get_public_key_bytes(compressed=False).hex()[0:66]+'...'
            except UninitializedSeedError:
                authentikey= None
                authentikey_comp= "This SeedKeeper is not initialized!"
            #card label 
            try:
                (response, sw1, sw2, card_label)= self.client.cc.card_get_label()
            except Exception as ex:
                card_label= str(ex)
        else:
            msg_status= 'No card found! please insert card!'
            
        frame_layout1= [
                                    [sg.Text('Card label: ', size=(20, 1)), sg.Text(card_label)],
                                    [sg.Text('Firmware Version: ', size=(20, 1)), sg.Text(fw_rel)],
                                    [sg.Text('Uses Secure Channel: ', size=(20, 1)), sg.Text(needs_SC)],
                                    [sg.Text('Authentikey: ', size=(20, 1)), sg.Text(authentikey_comp)],
                                    [sg.Button('Add Authentikey to TrustStore', key='add_authentikey', size= (20,1) )]]
        frame_layout2= [
                                    [sg.Text('Supported Version: ', size=(20, 1)), sg.Text(sw_rel)],
                                    [sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
        frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
        layout = [[sg.Frame('SeedKeeper', frame_layout1, font='Any 12', title_color='blue')],
                      [sg.Frame('SeedKeeper status', frame_layout2, font='Any 12', title_color='blue')],
                      [sg.Frame('About SeedKeeperUtil', frame_layout3, font='Any 12', title_color='blue')],
                      [sg.Button('Ok')]]
        
        window = sg.Window('SeedKeeperUtil: About', layout, icon=self.satochip_icon)    
        
        while True:
            event, values = window.read() 
            if event== 'add_authentikey':
                if authentikey is None:
                    self.show_error('No authentikey available!')
                elif authentikey in self.client.truststore:
                    self.show_success('Authentikey already in TrustStore!')
                else:
                    #self.client.truststore+=[authentikey]
                    self.client.truststore[authentikey]= card_label
                    self.show_success('Authentikey added to TrustStore!')
            if event=='Ok' or event=='Cancel':
                break
        
        #event, values = window.read()    
        window.close()  
        del window
    
####################################
#            SATOCHIP                               
####################################
     
    def QRDialog(self, data, parent=None, title = "QR code", show_text=False, msg= ''):
        logger.debug('In QRDialog')
        import pyqrcode
        code = pyqrcode.create(data)
        image_as_str = code.png_as_base64_str(scale=5, quiet_zone=2) #string
        image_as_str= base64.b64decode(image_as_str) #bytes
        
        layout = [[sg.Image(data=image_as_str, tooltip=None, visible=True)],
                        [sg.Text(msg)],
                        [sg.Button('Ok'), sg.Button('Cancel'), sg.Button('Copy 2FA-secret to clipboard')]]     
        window = sg.Window(title, layout, icon=self.satochip_icon)    
        while True:
            event, values = window.read()    
            if event=='Ok' or event=='Cancel':
                break
            elif event=='Copy 2FA-secret to clipboard':
                pyperclip.copy(data) 
                
        window.close()
        del window
        pyperclip.copy('') #purge 2FA from clipboard
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
    def reset_seed_dialog(self, msg):
        logger.debug('In reset_seed_dialog')
        layout = [[sg.Text(msg)],
                [sg.InputText(password_char='*', key='pin')], 
                [sg.Checkbox('Also reset 2FA', key='reset_2FA')], 
                [sg.Button('Ok'), sg.Button('Cancel')]]
        window = sg.Window("Reset seed", layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Ok
        #Values:<class 'dict'>{'passphrase': 'toto', 'reset_2FA': False}
        return (event, values)
    
    ### SEED Config ###
    def choose_seed_action(self):
        logger.debug('In choose_seed_action')
        layout = [
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Text("")],
            [sg.Text("Do you want to create a new seed, or to restore a wallet using an existing seed?")],
            [sg.Radio('Create a new seed', 'radio1', key='create')], 
            [sg.Radio('I already have a seed', 'radio1', key='restore')], 
            [sg.Button('Cancel'), sg.Button('Next')]
        ]
        window = sg.Window("Create or restore seed", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'create': True, 'restore': False}
        return (event, values)
        
    def create_seed(self, seed):    
        logger.debug('In create_seed')
        warning1= ("Please save these 12 words on paper (order is important). \nThis seed will allow you to recover your wallet in case of computer failure.")
        warning2= ("WARNING:")
        warning3= ("*Never disclose your seed.\n*Never type it on a website.\n*Do not store it electronically.")
        
        layout = [[sg.Text("Your wallet generation seed is:")],
                [sg.Multiline(seed, size=(60,3))], #[sg.Text(seed)], 
                [sg.Checkbox('Extends this seed with custom words', key='use_passphrase')], 
                [sg.Text(warning1)],
                [sg.Text(warning2)],
                [sg.Text(warning3)],
                [sg.Button('Back'), sg.Button('Next'), sg.Button('Copy seed to clipboard')]]
        window = sg.Window("Create seed", layout, icon=self.satochip_icon)        
        while True:
            event, values = window.read()    
            if event=='Back' or event=='Next' :
                break
            elif event=='Copy seed to clipboard':
                try:
                    pyperclip.copy(seed)
                except PyperclipException as e:
                    logger.warning("PyperclipException: "+ str(e))
                    self.client.request('show_error', "PyperclipException: "+ str(e))
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'use_passphrase': False}
        return (event, values)
        
    def request_passphrase(self):
        logger.debug('In request_passphrase')
        info1= ("You may extend your seed with custom words.\nYour seed extension must be saved together with your seed.")
        info2=("Note that this is NOT your encryption password.\nIf you do not know what this is, leave this field empty.")
        layout = [[sg.Text("Seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase')], 
                [sg.Text(info2)],
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Seed extension", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'passphrase': 'toto'}
        return (event, values)
        
        
    def confirm_seed(self):
        logger.debug('In confirm_seed')
        pyperclip.copy('') #purge clipboard to ensure that seed is backuped
        info1= ("Your seed is important! If you lose your seed, your money will be \npermanently lost. To make sure that you have properly saved your \nseed, please retype it here:")
        layout = [[sg.Text("Confirm seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Confirm seed", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def confirm_passphrase(self):
        logger.debug('In confirm_passphrase')
        info1= ("Your seed extension must be saved together with your seed.\nPlease type it here.")
        layout = [[sg.Text("Confirm seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Confirm seed extension", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def restore_from_seed(self):
        logger.debug('In restore_from_seed')
        from mnemonic import Mnemonic
        MNEMONIC = Mnemonic(language="english")
        
        info1= ("Please enter your BIP39 seed phrase in order to restore your wallet.")
        layout = [[sg.Text("Enter Seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed')], 
                [sg.Checkbox('Extends this seed with custom words', key='use_passphrase')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Enter seed", layout, icon=self.satochip_icon)        
        while True:
            event, values = window.read()    
            if event=='Next' :
                if not MNEMONIC.check(values['seed']):# check that seed is valid
                    self.client.request('show_error', "Invalid BIP39 seed! Please type again!")
                else:
                    break            
            else: #  event=='Back'
                break
        window.close()
        del window
        
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
    # communicate with other threads through queues
    def reply(self):    
        
        while not self.client.queue_request.empty(): 
            #logger.debug('Debug: check QUEUE NOT EMPTY')
            (request_type, args)= self.client.queue_request.get()
            logger.debug("Request in queue:" + str(request_type))
            for arg in args: 
                logger.debug("Next argument through *args :" + str(arg)) 
            
            method_to_call = getattr(self, request_type)
            #logger.debug('Type of method_to_call: '+ str(type(method_to_call)))
            #logger.debug('method_to_call: '+ str(method_to_call))
            
            reply = method_to_call(*args)
            self.client.queue_reply.put((request_type, reply))
                
    