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
     
####################################
#            SEEDKEEPER                               
####################################

    def main_menu(self):
        logger.debug('In main_menu')
        layout = [[sg.Text('Welcome to SeedKeeper Utility !')],      
                        [sg.Button('Generate a new seed')],
                        [sg.Button('Import a Secret')],
                        [sg.Button('Export a Secret')],
                        #[sg.Button('Export Secure Secret')],
                        #[sg.Button('Import Secure Secret')], 
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
        
    # def import_secret_menu_old(self):
        # logger.debug('In import_secret_menu')
        
        # import_list= ['BIP39 seed', 'Electrum seed', 'MasterSeed', 'Secure import from json', 'Public Key', 'Authentikey from TrustStore', 'Password']
        
        # layout = [
            # [sg.Text('Choose the type of secret you wish to import: ', size=(40, 1))],
            # [sg.Text('Type: ', size=(10, 1)), sg.InputCombo( import_list, key='type', size=(20, 1))],
            # [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in clear allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            # [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(20, 1))],
            # [sg.Submit(), sg.Cancel()]
        # ] 
        # window = sg.Window('SeedKeeper: import secret - Step 1', layout, icon=self.satochip_icon)  #ok
        # event, values = window.read()    
        # window.close()  
        # del window
        
        # return event, values
        
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
        
        layout = [
            [sg.Text('Choose the authentikey you wish to import from TrustStore: ', size=(40, 1))],
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(self.client.truststore, key='authentikey', size=(40, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
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
        
    # def export_secret_old(self):
        # logger.debug('In export_secret')
        # layout = [
            # [sg.Text('Id of the secret to export: '), sg.InputText(key='id', size=(10, 1))],
            # [sg.Text('Label: ', size=(10, 1)), sg.Text(key='label')],
            # [sg.Text('Fingerprint: ', size=(10, 1)), sg.Text(key='fingerprint')],
            # [sg.Text('Type: ', size=(10, 1)), sg.Text(key='type')],
            # [sg.Text('Origin: ', size=(10, 1)), sg.Text(key='origin')],
            # #[sg.Text(key='secret_field', size=(10, 1)), sg.Text(key='secret')],
            # #[sg.Text('Secret: ', key='secret_field', size=(10, 1)), sg.InputText(key='secret')],
            # #[sg.Text('Secret: ', key='secret_field', size=(10, 1)), sg.Multiline(key='secret', size=(20, 3) )],
            # [sg.Multiline(key='secret', size=(40, 3) )],
            # #[sg.Text(key='option_field', size=(10, 1)), sg.Text(key='secret2')],
            # [sg.Button('Export', bind_return_key=True), sg.Cancel()]
        # ]   
        
        # window = sg.Window('SeedKeeper export', layout)      
        # while True:      
            # event, values = window.read()      
            # logger.debug(f"event: {event}")
            # if event == 'Export':  #if event != 'Exit'  and event != 'Cancel':      
                # try:     
                    # sid= int(values['id'])
                # except Exception as ex:      
                    # self.show_error(f'Error during secret export: {ex}')
                    # continue
                    
                # try: 
                    # secret_dict= self.client.cc.seedkeeper_export_plain_secret(sid)
                    # #window['type'].update(secret_dict['type'])      
                    # window['fingerprint'].update(secret_dict['fingerprint'])      
                    # window['label'].update(secret_dict['label'])      
                    # if secret_dict['origin']==0x01:
                        # window['origin'].update('Plain import')      
                    # elif secret_dict['origin']==0x02:
                        # window['origin'].update('Secure import')   
                    # elif secret_dict['origin']==0x03:
                        # window['origin'].update('Generated on card')   
                    # else:
                        # window['origin'].update('Unknown')   
                    # #TODO: parse secret depending to type for all cases (in CardDataParser?)
                    # secret_list= secret_dict['secret']
                    # secret_size= secret_list[0]
                    # secret_raw= secret_list[1:1+secret_size]
                    # if (secret_dict['type']== 0x10): #Masterseed
                        # secret= bytes(secret_raw).hex()
                        # window['type'].update('Masterseed')      
                        # #window['secret_field'].update('Masterseed: ')    
                        # window['secret'].update(secret)    
                    # elif (secret_dict['type']== 0x30): #BIP39
                        # secret1= bytes(secret_raw).decode('utf-8')
                        # secret= "BIP39: " + secret1
                        # if len(secret_list)>=(2+secret_size): #passphrase
                            # secret_size2= secret_list[1+secret_size]
                            # secret_raw2= secret_list[2+secret_size:2+secret_size+secret_size2]
                            # secret2= bytes(secret_raw2).decode('utf-8')
                            # if len(secret2)>0:
                                # secret+= "\n" + "Passphrase: " + secret2
                        # window['type'].update('BIP39') 
                        # #window['secret_field'].update('BIP39: ')    
                        # window['secret'].update(secret)    
                        # #window['option_field'].update('Passphrase: ')    
                        # #window['secret2'].update(secret2)    
                    # elif (secret_dict['type']== 0x70): #pubkey
                        # secret= bytes(secret_raw).hex()
                        # window['type'].update('Pubkey') 
                        # #window['secret_field'].update('Pubkey: ')    
                        # window['secret'].update(secret)    
                    # elif (secret_dict['type']== 0x90): #password
                        # secret= bytes(secret_raw).decode('utf-8')
                        # window['type'].update('Password') 
                        # window['secret'].update(secret)   
                        # #window['secret_field'].update('Password: ')    
                    # else:
                        # secret= "Raw hex: "+secret_dict['secret_hex']
                        # #window['secret_field'].update('Secret: ')    
                        # window['type'].update('Unknown') 
                        # window['secret'].update(secret) 
                        
                # except (SeedKeeperError, UnexpectedSW12Error) as ex:
                    # #window['secret_field'].update('Secret: ')    
                    # window['secret'].update(str(ex))      
                    # window['type'].update("N/A")      
                    # window['fingerprint'].update("N/A")      
                    # window['label'].update("N/A")      
                
            # else:      
                # break      
            
        # window.close()  
        # del window
            
    def export_secret(self):
        logger.debug('In export_secret')
        
        # get a list of all the secrets & pubkeys available
        label_list=[]
        id_list=[]
        label_pubkey_list=['None (export to plaintext)']
        id_pubkey_list=[None]
        try:
            headers= self.client.cc.seedkeeper_list_secret_headers()
            for header_dic in headers:
                label_list.append( header_dic['fingerprint'] + ': '  + header_dic['label'] )
                id_list.append( header_dic['id'] )
                if header_dic['type']==0x70:
                    pubkey_dic= self.client.cc.seedkeeper_export_secret(header_dic['id'], None) #export pubkey in plain
                    pubkey= pubkey_dic['secret_hex'][2:10]
                    label_pubkey_list.append( header_dic['fingerprint'] + ': '  + header_dic['label'] + ' - ' + pubkey + '...')
                    id_pubkey_list.append( header_dic['id'] )
        except Exception as ex:      
            self.show_error(f'Error during secret export: {ex}')
            return
            
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
    
    def logs_menu(self):
        logger.debug('In logs_menu')
        
        try:
            (logs, nbtotal_logs, nbavail_logs)= self.client.cc.seedkeeper_print_logs(print_all=True)
        except Exception as ex:      
            self.show_error(f'Error during logs export: {ex}')
            return
            
        #TODO: nice presentation instead of raw data
        
        txt= ''
        txt+= f'Total number of events recorded: {nbtotal_logs} \n'
        txt+= f'Number of records available: {nbavail_logs} \n\n'
        
        for log in logs:
            txt+= str(log)+'\n'
            
        layout = [[sg.Multiline(txt, size=(45,20))],
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
        
        txt= ''
        txt+= f'Number of secrets stored: {len(headers)} \n\n'
        
        for header in headers:
            sid= str(header['id'])
            stype= hex(header['type'])
            origin= hex(header['origin'])
            export_rights= str(header['export_rights'])
            export_nbplain= str(header['export_nbplain'])
            export_nbsecure= str(header['export_nbsecure'])
            fingerprint= header['fingerprint']
            label= header['label']
            
            txt+= f'id: {sid} - '
            txt+= f'type: {stype} - '
            txt+= f'origin: {origin} - '
            txt+= f'export_rights: {export_rights} - '
            txt+= f'export_nbplain: {export_nbplain} - '
            txt+= f'export_nbsecure: {export_nbsecure} - '
            txt+= f'fingerprint: {fingerprint} - '
            txt+= f'label: {label} - '
            txt+='\n'
        
        layout = [[sg.Multiline(txt, size=(45,20))],
                      [sg.Button('Ok')],
                    ]
        window = sg.Window('SeedKeeperUtil Secret headers', layout, icon=self.satochip_icon)  #ok
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
        msg_status= ("Card is not initialized! \nClick on 'Setup new Satochip' in the menu to start configuration.")
            
        (response, sw1, sw2, status)=self.client.cc.card_get_status()
        if (sw1==0x90 and sw2==0x00):
            #hw version
            v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
            fw_rel= str(status["protocol_major_version"]) +'.'+ str(status["protocol_minor_version"] )
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
                authentikey_pubkey=self.client.cc.card_bip32_get_authentikey()
                authentikey_bytes= authentikey_pubkey.get_public_key_bytes(compressed=False)
                authentikey= authentikey_bytes.hex()
                authentikey_comp= authentikey_pubkey.get_public_key_bytes(compressed=True).hex()
            except UninitializedSeedError:
                authentikey= None
                authentikey_comp= "This SeedKeeper is not initialized!"
                
        else:
            msg_status= 'No card found! please insert card!'
            
        frame_layout1= [[sg.Text('Supported Version: ', size=(20, 1)), sg.Text(sw_rel)],
                                    [sg.Text('Firmware Version: ', size=(20, 1)), sg.Text(fw_rel)],
                                    #[sg.Text('Wallet is seeded: ', size=(20, 1)), sg.Text(is_seeded)],
                                    #[sg.Text('Requires 2FA: ', size=(20, 1)), sg.Text(needs_2FA)],
                                    [sg.Text('Uses Secure Channel: ', size=(20, 1)), sg.Text(needs_SC)],
                                    [sg.Text('Authentikey: ', size=(20, 1)), sg.Text(authentikey_comp)],
                                    [sg.Button('Add Authentikey to TrustStore', key='add_authentikey', size= (20,1) )]]
        frame_layout2= [[sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
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
                    self.client.truststore+=[authentikey]
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
                
    