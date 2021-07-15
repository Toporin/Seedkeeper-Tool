#import PySimpleGUI as sg   
#import PySimpleGUIWx as sg 
import PySimpleGUIQt as sg 
import base64  #todo:remove  
import json
import getpass
import sys
import os
import logging
#from queue import Queue #todo: remove
from mnemonic import Mnemonic

from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.CardConnector import CardConnector
from pysatochip.CardConnector import UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error, CardError
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION
from pysatochip.version import SEEDKEEPER_PROTOCOL_MAJOR_VERSION, SEEDKEEPER_PROTOCOL_MINOR_VERSION, SEEDKEEPER_PROTOCOL_VERSION
from pysatochip.version import PYSATOCHIP_VERSION

# print("DEBUG START handler.py ")
# print("DEBUG START handler.py __name__: "+__name__)
# print("DEBUG START handler.py __package__: "+str(__package__))

try: 
    import electrum_mnemonic
    from version import SEEDKEEPERTOOL_VERSION
except Exception as e:
    print('handler.py importError: '+repr(e))
    from . import electrum_mnemonic
    from .version import SEEDKEEPERTOOL_VERSION
    
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
  
class HandlerTxt:
    def __init__(self):
        pass

    def update_status(self, isConnected):
        if (isConnected):
            print("Card connected!")
            self.client.card_event=True
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
        
        # if self.client.cc.card_present:
            # self.tray = sg.SystemTray(filename=self.satochip_icon) 
        # else:
            # self.tray = sg.SystemTray(filename=self.satochip_unpaired_icon) 
        self.tray = sg.SystemTray(filename=self.satochip_icon) 
         
         
    def icon_path(self, icon_basename):
        #return resource_path(icon_basename)
        return os.path.join(self.pkg_dir, icon_basename)
    
    # CAUTION: update_status is called from another thread and in principle, no gui is allowed outside of the main thread
    def update_status(self, isConnected):
        logger.debug('In update_status')
        self.client.card_event=True #trigger update of GUI 
        #if (isConnected):
            #self.tray.update(filename=self.satochip_icon) #self.tray.update(filename=r'satochip.png')
        #else:
            #self.tray.update(filename=self.satochip_unpaired_icon) #self.tray.update(filename=r'satochip_unpaired.png')
         
    def show_error(self, msg):
        sg.popup('Error!', msg, icon=self.satochip_unpaired_icon)
    def show_success(self, msg):
        sg.popup('Success!', msg, icon=self.satochip_icon)
    def show_message(self, msg):
        sg.popup('Notification', msg, icon=self.satochip_icon)
    def show_notification(self, title, msg):
        #logger.debug("START show_notification")
        #self.tray.ShowMessage("Notification", msg, filename=self.satochip_icon, time=10000) #old
        # self.tray.ShowMessage("Notification", msg, messageicon=sg.SYSTEM_TRAY_MESSAGE_ICON_INFORMATION, time=100000)
        
        self.tray.ShowMessage(title, msg, time=100000)
        #sg.popup_quick_message('popup_quick_message')
        
        #self.tray.notify(title, msg) # AttributeError: 'SystemTray' object has no attribute 'notify'
        #sg.popup_notify(title, display_duration_in_ms=3000, fade_in_duration=1000, alpha=0.9, location=None) #nok
        #sg.SystemTray.notify(title, msg) # AttributeError: type object 'SystemTray' has no attribute 'notify'
        #sg.SystemTray.show_message(title=title, message=msg)
        #logger.debug("END show_notification")
        
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
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        #window = sg.Window('Confirmation required', layout, icon="satochip.ico")    #ok
        event, values = window.read()    
        window.close()  
        del window
        
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
     
    def QRDialog(self, data, title = "SeedKeeperTool: QR code", msg= ''):
        logger.debug('In QRDialog')
        import pyqrcode
        code = pyqrcode.create(data)
        image_as_str = code.png_as_base64_str(scale=5, quiet_zone=2) #string
        image_as_str= base64.b64decode(image_as_str) #bytes
        
        layout = [[sg.Image(data=image_as_str, tooltip=None, visible=True)],
                        [sg.Text(msg)],
                        [sg.Button('Ok'), sg.Button('Cancel')]]     
        window = sg.Window(title, layout, icon=self.satochip_icon)    
        event, values = window.read()        
        window.close()
        del window
        return (event, values) 
     
    def setup_card(self):
        logger.debug('In setup_card')
        layout = [
                        #[sg.Text(f'Your {self.client.cc.card_type} needs to be set up! This mùust be done only once.')],      
                        [sg.Text(f'Please take a moment to set up your {self.client.cc.card_type}. This must be done only once.')],      
                        [sg.Text('Enter new PIN: ', size=(16,1)), sg.InputText(password_char='*', key='pin')],      
                        [sg.Text('Confirm PIN: ', size=(16,1)), sg.InputText(password_char='*', key='pin2')],      
                        [sg.Text('Enter card label (optional): ', size=(16,1)), sg.InputText(key='card_label')],      
                        [sg.Text(size=(40,1), key='-OUTPUT-', text_color='red')],
                        [sg.Submit(), sg.Cancel()]]     
                        
        window = sg.Window('Setup new card', layout, icon=self.satochip_icon)    
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    pin= values['pin']
                    pin2= values['pin2']
                    if pin != pin2:
                        raise ValueError("WARNING: the PIN values do not match! Please type PIN again!")
                    elif len(pin) < 4:
                        raise ValueError("WARNING: the PIN must have at least 4 characters!")
                    elif len(pin) > 16:
                        raise ValueError("WARNING: the PIN must have less than 16 characters!") 
                    label= values['card_label']
                    if len(label)>64:
                        raise ValueError(f"WARNING: label must have less than 64 characters! Choose another label.")
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) 
                
        window.close()
        del window
        return event, values
    
####################################
#            SEEDKEEPER                         #      
####################################

    def main_menu(self):
        logger.debug('In main_menu')
        
        button_color_enabled= ('#912CEE', '#B2DFEE') # purple2, lighblue2 - see https://github.com/PySimpleGUI/PySimpleGUI/blob/master/DemoPrograms/Demo_Color_Chooser_Custom.py
        button_color_disabled= ('White', 'Gray')
        disabled=[False]*6
        color= [button_color_enabled]*6
        #buttons=['Generate_new_seed', 'import_secret', 'export_secret', 'make_backup', 'list_secrets', 'get_logs']
        buttons=['generate_oncard', 'import_secret', 'export_secret', 'make_backup', 'list_secrets', 'get_logs']
        
        def update_button(do_update_layout=False):
            nonlocal disabled, color
            logger.debug("Update_button - Card reader status: "+ str(self.client.cc.card_type))
            
            if self.client.cc.card_type=='SeedKeeper':
                disabled=[False]*6
                color= [button_color_enabled]*6
            elif self.client.cc.card_type=='Satochip':
                disabled=[True]*6
                disabled[1]=False
                color= [button_color_disabled]*6
                color[1]= button_color_enabled
            else: #no card
                disabled=[True]*6
                color= [button_color_disabled]*6
            if (do_update_layout):
                logger.debug("Update layout!")
                for index, button in enumerate(buttons):
                    window[button].update(disabled=disabled[index])
                    window[button].update(button_color=color[index]) 
        
        layout = [[sg.Text('Welcome to SeedKeeper Tool !')],  
                        #[sg.Text('Card inserted:' + str(self.client.cc.card_type))],          
                        #[sg.Button('Generate a new Masterseed', disabled= disabled[0], button_color=color[0], key=buttons[0]) ],
                        [sg.Button('Generate Secret on-card', disabled= disabled[0], button_color=color[0], key=buttons[0]) ],
                        [sg.Button('Import a Secret', disabled= disabled[1], button_color=color[1], key=buttons[1])],
                        [sg.Button('Export a Secret', disabled= disabled[2], button_color=color[2], key=buttons[2])],
                        [sg.Button('Make a backup', disabled= disabled[3], button_color=color[3], key=buttons[3])],
                        [sg.Button('List Secrets', disabled= disabled[4], button_color=color[4], key=buttons[4])],
                        [sg.Button('Get logs', disabled= disabled[5], button_color=color[5], key=buttons[5])],
                        [sg.Button('About', disabled= False, button_color=button_color_enabled, key='about')],
                        [sg.Button('Help', disabled= False, button_color=button_color_enabled, key='help')],
                        [sg.Button('Quit', disabled= False, button_color=button_color_enabled, key='quit')],
                    ]      
        window = sg.Window('SeedKeeper Tool', layout, icon=self.satochip_icon).Finalize()   #ok
        update_button(True)
        
        while True:
            event, values = window.read(timeout=200)    
            if (self.client.card_event):
                update_button(True)
                self.client.card_init_connect()
                self.client.card_event= False
                continue
            if event != sg.TIMEOUT_KEY:
                break
                
        window.close()  
        del window
        return event
        
    def generate_oncard_menu(self):
        logger.debug('In generate_oncard_menu')
        
        if self.client.cc.card_type=='SeedKeeper':
            import_list=['Masterseed', '2FA Secret']
        elif self.client.cc.card_type=='Satochip':
            import_list=['(On-card generation not supported for Satochip)']
        else:
            import_list=['(no card inserted)']
            
        layout = [
            [sg.Text('Choose the type of secret you wish to generate: ', size=(30, 1))],
            #[sg.Text('Type: ', size=(10, 1)), sg.InputCombo( import_list, key='type', size=(20, 1))],
            [sg.Listbox( import_list, key='type', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, size=(30, 7))],
            [sg.Submit(), sg.Cancel()]
        ] 
        window = sg.Window('SeedKeeper: generate secret - Step 1', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        return event, values
        
    def generate_new_seed(self):
        logger.debug('In generate_new_seed')
        layout = [
            [sg.Text('Please enter masterseed settings below: ')],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(20, 1))],
            [sg.Text('Size: ', size=(10, 1)), sg.InputCombo(('16 bytes' , '32 bytes', '48 bytes', '64 bytes'), key='size', size=(20, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ]   
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        # check label 
        if len(values['label']) >127: 
            values['label']= values['label'][0:127]
        return event, values
     
         
    def generate_new_2FA_secret(self):
        logger.debug('In generate_new_2FA_secret')
        layout = [
            [sg.Text('Please enter 2FA settings below: ')],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(20, 1))],
            [sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ]   
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        # check label 
        if len(values['label']) >127: 
            values['label']= values['label'][0:127]
        return event, values
     
    def import_secret_menu(self):
        logger.debug('In import_secret_menu')
        
        if self.client.cc.card_type=='SeedKeeper':
            import_list=['Mnemonic phrase', 'Masterseed', 'Secure import from json', 'Authentikey from TrustStore', 'Trusted Pubkey', 'Password']
        elif self.client.cc.card_type=='Satochip':
            import_list=['Mnemonic phrase', 'Masterseed', 'Secure import from json', 'Authentikey from TrustStore', 'Trusted Pubkey']
        else:
            import_list=['(no card inserted)']
            
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
            [sg.Text('Enter the masterseed as a hex string with 32, 64, 96 or 128 characters: ', size=(45, 1))],
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
                    #limit label size to 127 max
                    if len(values['label']) >127:
                        raise ValueError(f"Label length should be strictly lower than 128")
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
    
    def choose_masterseed_from_list(self, masterseed_list):
        logger.debug("In choose_masterseed_from_list")
        layout = [
                      [sg.Text('Choose the masterseed to import from this list:', size=(60,1))],
                      [sg.Listbox( masterseed_list, key='masterseed_list', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, size=(60, 8))],
                      [sg.Submit(), sg.Cancel()],
                    ]
        window = sg.Window('SeedKeeper Tool', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window      
        return event, values

    def choose_secret_from_list(self, secret_list):
        logger.debug("In choose_secret_from_list")
        layout = [
                      [sg.Text('Choose the secret to import from this list:', size=(60,1))],
                      [sg.Listbox( secret_list, key='secret_list', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, size=(60, 8))],
                      [sg.Submit(), sg.Cancel()],
                    ]
        window = sg.Window('SeedKeeper Tool', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window      
        return event, values
     
    def import_secret_pubkey(self):    
        logger.debug("In import_secret_pubkey")
        layout = [
            [sg.Text('Enter the pubkey as a hex string: ', size=(40, 1))],
            [sg.Text('Hex value: ', size=(10, 1)), sg.InputText(key='pubkey', size=(68, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            #[sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
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
                    #check pubkey
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
                    #check label
                    if len(values['label']) >127:
                        raise ValueError(f'Label length should be strictly lower than 128!')
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
                
        window.close()
        del window
        
        values['export_rights']= 'Export in plaintext allowed' # a public key should be exportable in plaintext for audit purpose...
        return event, values
    
    def import_secret_authentikey(self):
        logger.debug("import_secret_authentikey")
        
        list_authentikey_label, list_authentikey= self.client.get_truststore_list()
        if len(list_authentikey_label)==0:
            self.show_message(f"No Authentikey found in TrustStore.\nOperation cancelled!")
            event='Cancel'
            return event, None
        
        layout = [
            [sg.Text('Choose the authentikey you wish to import from TrustStore: ', size=(60, 1))],
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(list_authentikey_label, key='pubkey', size=(40, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(key='label', size=(40, 1))],
            #[sg.Text('Export rights: ', size=(10, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(20, 1))],
            [sg.Submit(), sg.Cancel()]
        ] 
        window = sg.Window('SeedKeeper: import secret - Step 2', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        
        if len(values['label']) >127: # check label 
            values['label']= values['label'][0:127]
        values['export_rights']= 'Export in plaintext allowed' # a public key should be exportable in plaintext for audit purpose...
        values['pubkey']= list_authentikey[list_authentikey_label.index(values['pubkey'])] 
        #values['card_label']= list_card_label[list_authentikey.index(values['pubkey'])] 
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
        
        # check label 
        if len(values['label']) >127:
            values['label']= values['label'][0:127]
        return event, values
            
    def export_secret(self):
        logger.debug('In export_secret')
        
        # get a list of all the secrets & pubkeys available
        (label_list, id_list, label_pubkey_list, id_pubkey_list)= self.client.get_secret_header_list()
        
        if len(label_list)==0:
            self.show_message(f'SeedKeeper is empty - No secret to export!')
            return
        
        layout = [
            [sg.Text('Secret to export: ', size=(10, 1)), sg.InputCombo(label_list, key='label_list', size=(50, 1)) ], 
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(label_pubkey_list, key='label_pubkey_list', size=(50, 1)) ],
            [sg.Text('Label: ', size=(10, 1)), sg.Text(key='label')],
            [sg.Text('Fingerprint: ', size=(10, 1)), sg.Text(key='fingerprint')],
            [sg.Text('Type: ', size=(10, 1)), sg.Text(key='type')],
            [sg.Text('Origin: ', size=(10, 1)), sg.Text(key='origin')],
            [sg.Multiline(key='secret', size=(60, 4) )],
            [sg.Button('Export', bind_return_key=True), sg.Button('Show QR Code', key='show_qr'), sg.Button('Close') ] # sg.Cancel()
        ]   
        
        window = sg.Window('SeedKeeper export', layout, icon=self.satochip_icon)      
        secret=''
        while True:      
            event, values = window.read()      
            logger.debug(f"event: {event}")
            if event == 'Export':  #if event != 'Exit'  and event != 'Close':      
                try:     
                    label= values['label_list']
                    sid= id_list[ label_list.index(label) ]
                    label_pubkey= values['label_pubkey_list']
                    sid_pubkey= id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]
                except Exception as ex:      
                    self.show_error(f'Error during secret export: {ex}')
                    continue
                
                # add authentikey from truststore
                if isinstance(sid_pubkey, str): 
                    authentikey= sid_pubkey
                    authentikey_list= list( bytes.fromhex(authentikey) )
                    secret= [len(authentikey_list)] + authentikey_list
                    label= self.client.truststore.get(authentikey,{}).get('card_label', '') + ' authentikey'#self.client.truststore[authentikey] + ' authentikey'
                    header= self.client.make_header('Authentikey from TrustStore', 'Export in plaintext allowed', label)
                    secret_dic={'header':header, 'secret':secret}
                    (sid_pubkey, fingerprint) = self.client.cc.seedkeeper_import_secret(secret_dic)
                    self.show_notification('Information: ', f"Authentikey '{label}' imported from TrustStore with id {sid_pubkey}")
                    # update sid_pubkey in id_pubkey_list to reflect change (so that authentikey is only imported once from truststore to device...)
                    id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]= sid_pubkey
                    
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
                    secret_list= secret_dict['secret_list']
                    
                    #plain export
                    if sid_pubkey is None: 
                        secret_size= secret_list[0]
                        secret_raw= secret_list[1:1+secret_size]
                        if (secret_dict['type']== 0x10): #Masterseed
                            secret= bytes(secret_raw).hex()
                            window['type'].update('Masterseed')      
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
                            window['type'].update('BIP39 mnemonic') 
                            window['secret'].update(secret)    
                        elif (secret_dict['type']== 0x40): #Electrum
                            secret1= bytes(secret_raw).decode('utf-8')
                            secret= "Electrum: " + secret1
                            if len(secret_list)>=(2+secret_size): #passphrase
                                secret_size2= secret_list[1+secret_size]
                                secret_raw2= secret_list[2+secret_size:2+secret_size+secret_size2]
                                secret2= bytes(secret_raw2).decode('utf-8')
                                if len(secret2)>0:
                                    secret+= "\n" + "Passphrase: " + secret2
                            window['type'].update('Electrum mnemonic') 
                            window['secret'].update(secret)    
                        elif (secret_dict['type']== 0x70): #pubkey
                            secret= bytes(secret_raw).hex()
                            window['type'].update('Pubkey') 
                            window['secret'].update(secret)    
                        elif (secret_dict['type']== 0x90): #password
                            secret= bytes(secret_raw).decode('utf-8')
                            window['type'].update('Password') 
                            window['secret'].update(secret)   
                        elif (secret_dict['type']== 0xA0): #certificate
                            secret= "Raw hex: "+bytes(secret_list).hex() #TODO
                            window['type'].update('Certificate') 
                            window['secret'].update(secret)   
                        elif (secret_dict['type']== 0xB0): #2FA
                            secret= bytes(secret_raw).hex()
                            window['type'].update('2FA') 
                            window['secret'].update(secret)   
                        else:
                            secret= "Raw hex: "+bytes(secret_list).hex()
                            window['type'].update('Unknown') 
                            window['secret'].update(secret) 
                    
                    # secure export print json of Secret?
                    else: 
                        window['type'].update('Encrypted Secret') 
                        try:
                            secret_dict_pubkey= self.client.cc.seedkeeper_export_secret(sid_pubkey)
                            authentikey_importer= secret_dict_pubkey['secret'][2:]
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
                                                    'header': secret_dict['header'], #bytes(secret_dict['header']).hex(), 
                                                    'iv': secret_dict['iv'], #bytes(secret_dict['iv']).hex(), 
                                                    'secret_encrypted': secret_dict['secret_encrypted'], #bytes(secret_list).hex(),  #'secret_base64':base64.encodebytes( bytes(secret_list) ).decode('utf8')
                                                    'hmac': secret_dict['hmac'], #bytes(secret_dict['hmac']).hex(), 
                                                }],
                                            }
                        secret= json.dumps(secret_obj)
                        window['secret'].update(secret)   
                        
                        
                except (SeedKeeperError, UnexpectedSW12Error) as ex:
                    window['secret'].update(str(ex))      
                    window['type'].update("N/A")      
                    window['fingerprint'].update("N/A")      
                    window['label'].update("N/A")    
                    window['origin'].update("N/A")   
            
            elif event=='show_qr':
                data= secret
                self.QRDialog(data, title = "SeedKeeperTool: QR code", msg= '')
            
            else:      
                break      
            
        window.close()  
        del window
    
    def make_backup(self):
        logger.debug('In backup_menu')
        
        (label_list, id_list, label_pubkey_list, id_pubkey_list)= self.client.get_secret_header_list()
        label_pubkey_list=label_pubkey_list[1:] # remove (none) value and id
        id_pubkey_list=id_pubkey_list[1:]
        
        # skip if if no authentikey is available for export
        if len(label_pubkey_list)==0:
            self.show_error("No authentikey available for encrypted export. \nInsert a backup SeedKeeper for pairing or import a Trusted Pubkey first!")
            return
        
        layout = [
            #[sg.Text('Secrets to export: ', size=(10, 1)), sg.InputCombo(type_list, key='type_list', size=(40, 1)) ], 
            [sg.Text('Authentikey: ', size=(10, 1)), sg.InputCombo(label_pubkey_list, key='label_pubkey_list', size=(40, 1)) ],
            [sg.Multiline(key='secret', size=(60, 8) )],
            [sg.Text('Number of secrets exported: ', size=(20, 1)), sg.Text(key='nb_secrets'), 
                sg.Text('Number of errors: ', size=(20, 1), visible=False), sg.Text(key='nb_errors', visible=True)],
            [sg.Button('Backup', bind_return_key=True), sg.Button('Close') ] # sg.Cancel()
        ]   
        
        window = sg.Window('SeedKeeper backup', layout, icon=self.satochip_icon)     
        backup=''
        while True:      
            event, values = window.read()      
            logger.debug(f"event: {event}")
            if event == 'Backup':  #if event != 'Exit'  and event != 'Close':      
                
                #get trusted authentikey from device or truststore
                label_pubkey= values['label_pubkey_list']
                sid_pubkey= id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]
                if isinstance(sid_pubkey, int): # from device
                    try:
                        secret_dict_pubkey= self.client.cc.seedkeeper_export_secret(sid_pubkey)
                        authentikey_importer= secret_dict_pubkey['secret'][2:]
                    except Exception as ex:
                        logger.warning('Exception during authentikey export: '+str(ex))
                        authentikey_importer= "(unknown)"
                elif isinstance(sid_pubkey, str): #from truststore 
                    try:
                        authentikey_importer= sid_pubkey
                        authentikey_list= list( bytes.fromhex(authentikey_importer) )
                        secret= [len(authentikey_list)] + authentikey_list
                        label= self.client.truststore.get(authentikey_importer,{}).get('card_label', '') + ' authentikey' #self.client.truststore[authentikey_importer] + ' authentikey'
                        header= self.client.make_header('Authentikey from TrustStore',  'Export in plaintext allowed', label)
                        secret_dic={'header':header, 'secret':secret}
                        (sid_pubkey, fingerprint) = self.client.cc.seedkeeper_import_secret(secret_dic)
                        self.show_notification('Information: ', f"Authentikey '{label} imported from TrustStore with id {sid_pubkey}")
                        # update sid_pubkey in id_pubkey_list to reflect change (so that authentikey is only imported once from truststore to device...)
                        id_pubkey_list[ label_pubkey_list.index(label_pubkey) ]= sid_pubkey
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
                        logger.warning(f'Debug sid_pubkey: {sid_pubkey} of type: {type(sid_pubkey)}')#debug
                        secret_dict= self.client.cc.seedkeeper_export_secret(sid, sid_pubkey)
                        secret= {  
                                        'label': secret_dict['label'], 
                                        'type': secret_dict['type'],    
                                        'fingerprint': secret_dict['fingerprint'], 
                                        'header': secret_dict['header'], #bytes(secret_dict['header']).hex(), 
                                        'iv': secret_dict['iv'], #bytes(secret_dict['iv']).hex(), 
                                        'secret_encrypted': secret_dict['secret_encrypted'], #bytes(secret_list).hex(), 
                                        'hmac': secret_dict['hmac'], #bytes(secret_dict['hmac']).hex(), 
                                    }
                        secrets_obj['secrets'].append(secret)
                        nb_secrets+=1
                        window['nb_secrets'].update(nb_secrets)   
                    except (SeedKeeperError, UnexpectedSW12Error, Exception) as ex:
                        logger.warning('Exception during secret export: '+str(ex))#debug
                        secret= {  'error': str(ex) }
                        secrets_obj['secrets'].append(secret)
                        nb_errors+=1
                        window['nb_errors'].update(nb_errors, visible=True) 
                        
                backup= json.dumps(secrets_obj)
                window['secret'].update(backup)   
                window['nb_secrets'].update(nb_secrets)   
                window['nb_errors'].update(nb_errors) 
                
            else:      
                break      
            
        window.close()  
        del window
                
        return backup
    
    def logs_menu(self):
        logger.debug('In logs_menu')
        ins_dic={0x40:'Create PIN', 0x42:'Verify PIN', 0x44:'Change PIN', 0x46:'Unblock PIN', 
                        0xA0:'Generate masterseed', 0xA5:'Reset secret', 0xAE:'Generate 2FA Secret',
                        0xA1:'Import secret', 0xA1A:'Import plain secret', 0xA1B:'Import encrypted secret', 
                        0xA2:'Export secret', 0xA2A:'Export plain secret', 0xA2B:'Export encrypted secret',
                        0xFF:'RESET TO FACTORY'}
        res_dic={0x9000:'OK', 0x63C0:'PIN failed', 0x9C03:'Operation not allowed', 0x9C04:'Setup not done', 0x9C05:'Feature unsupported', 
                        0x9C01:'No memory left', 0x9C08:'Secret not found', 0x9C10:'Incorrect P1', 0x9C11:'Incorrect P2', 0x9C0F:'Invalid parameter',
                        0x9C0B:'Invalid signature', 0x9C0C:'Identity blocked', 0x9CFF:'Internal error', 0x9C30:'Lock error', 0x9C31:'Export not allowed',
                        0x9C32:'Import data too long', 0x9C33:'Wrong MAC during import', 0x0000:'Unexpected error'}                
        
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
        
        if len(strlogs)==0:
            strlogs.append(['', '', '', ''])
        
        txt1= f'Number of events recorded: {nbtotal_logs} out of {nbavail_logs} available'
        layout = [
                      [sg.Text(txt1, size=(60,1))],
                      [sg.Table(strlogs, headings=headings)],
                      [sg.Button('Ok')],
                    ]
        window = sg.Window('SeedKeeper Logs', layout, icon=self.satochip_icon)  #ok
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
            
        # nice presentation instead of raw data
        txt= f'Number of secrets stored: {len(headers)}'
        headings=['Id', 'Label', 'Type', 'Origin', 'Export rights', 'Nb plain exports', 'Nb encrypted exports', 'Nb secret exported', 'Fingerprint']
        dic_type= {0x30:'BIP39 mnemonic', 0x40:'Electrum mnemonic', 0x10:'Masterseed', 0x70:'Public Key', 0x90:'Password', 0xA0:'Authentikey certificate', 0xB0:'2FA secret'}
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
        
        if len(strheaders)==0:
            strheaders.append(['', '', '', '', '', '', '', '', ''])
         
        layout = [
                      [sg.Text(txt, size=(60,1))],
                      [sg.Table(strheaders, headings=headings, display_row_numbers=False, key='_TABLE_')],
                      [sg.Button('Ok')],
                    ]
        window = sg.Window('SeedKeeper Secret Headers', layout, icon=self.satochip_icon).Finalize()  #ok
        # workaround for bug: https://github.com/PySimpleGUI/PySimpleGUI/issues/1422
        # if window.Element('_TABLE_').DisplayRowNumbers == True:
            # window.Element('_TABLE_').QT_TableWidget.verticalHeader().show()
        # else:
            # window.Element('_TABLE_').QT_TableWidget.verticalHeader().hide()
        
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
        v_supported_satochip= SATOCHIP_PROTOCOL_VERSION
        sw_rel_satochip= str(SATOCHIP_PROTOCOL_MAJOR_VERSION) +'.'+ str(SATOCHIP_PROTOCOL_MINOR_VERSION)
        v_supported_seedkeeper= SEEDKEEPER_PROTOCOL_VERSION
        sw_rel_seedkeeper= str(SEEDKEEPER_PROTOCOL_MAJOR_VERSION) +'.'+ str(SEEDKEEPER_PROTOCOL_MINOR_VERSION)
        fw_rel= "N/A"
        is_seeded= "N/A"
        needs_2FA= "N/A"
        needs_SC= "N/A"
        authentikey= None
        authentikey_comp= "N/A"
        card_label= "N/A"
        #msg_status= ("Card is not initialized! \nClick on 'Setup new Satochip' in the menu to start configuration.")
         
        if (self.client.cc.card_present):
            (response, sw1, sw2, status)=self.client.cc.card_get_status()
            if (sw1==0x90 and sw2==0x00):
                #hw version
                v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
                fw_rel= str(status["protocol_major_version"]) +'.'+ str(status["protocol_minor_version"])  +' - '+ str(status["applet_major_version"]) +'.'+ str(status["applet_minor_version"])
                # status
                if (self.client.cc.card_type=='Satochip' and v_supported_satochip<v_applet):
                    msg_status=(f'The version of your Satochip is higher than supported. \nYou should update SeedKeeperTool!')
                elif (self.client.cc.card_type=='SeedKeeper' and v_supported_seedkeeper<v_applet):
                    msg_status=(f'The version of your SeedKeeper is higher than supported. \nYou should update SeedKeeperTool!')
                else:
                    msg_status= 'SeedKeeperTool is up-to-date'
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
                    authentikey_pubkey= self.client.cc.card_export_authentikey() # self.client.authentikey #
                    authentikey_bytes= authentikey_pubkey.get_public_key_bytes(compressed=False)
                    authentikey= authentikey_bytes.hex()
                    authentikey_comp= authentikey_pubkey.get_public_key_bytes(compressed=True).hex()
                except UninitializedSeedError:
                    authentikey= None
                    authentikey_comp= "This SeedKeeper is not initialized!"
                except UnexpectedSW12Error as ex:
                    authentikey= None
                    authentikey_comp= str(ex)
                    #self.show_error(str(ex))
                #card label 
                try:
                    (response, sw1, sw2, card_label)= self.client.cc.card_get_label()
                except Exception as ex:
                    card_label= str(ex)
            else: 
                msg_status= f'Unexpected error while polling card: error code {hex(sw1)} {hex(sw2)}'
        else:
            msg_status= 'No card found! please insert card!'
            
        frame_layout1= [
                                    [sg.Text('Card label: ', size=(20, 1)), sg.Text(card_label)],
                                    [sg.Text('Firmware version: ', size=(20, 1)), sg.Text(fw_rel)],
                                    [sg.Text('Uses Secure Channel: ', size=(20, 1)), sg.Text(needs_SC)],
                                    [sg.Text('Authentikey: ', size=(20, 1)), sg.Text(authentikey_comp)],
                                    [sg.Button('Show TrustStore', key='show_truststore', size= (20,1) ),  sg.Button('Verify Card', key='verify_card', size= (20,1) )]]
        frame_layout2= [
                                    [sg.Text('Supported version (SeedKeeper): ', size=(20, 1)), sg.Text(sw_rel_seedkeeper)],
                                    [sg.Text('Supported version (Satochip): ', size=(20, 1)), sg.Text(sw_rel_satochip)],
                                    [sg.Text('SeedKeeperTool version: ', size=(20, 1)), sg.Text(SEEDKEEPERTOOL_VERSION)],
                                    [sg.Text('Pysatochip version: ', size=(20, 1)), sg.Text(PYSATOCHIP_VERSION)],
                                    [sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
        frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
        layout = [[sg.Frame(self.client.cc.card_type, frame_layout1, font='Any 12', title_color='blue')],
                      [sg.Frame('SeedKeeperTool status', frame_layout2, font='Any 12', title_color='blue')],
                      [sg.Frame('About SeedKeeperTool', frame_layout3, font='Any 12', title_color='blue')],
                      [sg.Button('Ok')]]
        
        window = sg.Window('SeedKeeperTool: About', layout, icon=self.satochip_icon)    
        
        while True:
            event, values = window.read() 
            if event== 'show_truststore':
                headings=['Fingerprint', 'Card label', 'Authentikey']
                truststore_list=[]
                for authentikey, dic_info in self.client.truststore.items():
                    fingerprint= dic_info['fingerprint']
                    card_label= dic_info['card_label']
                    authentikey_comp= dic_info['authentikey_comp']
                    truststore_list.append([fingerprint, card_label, authentikey_comp])
                if len(truststore_list)>0:
                    layout2 = [
                          [sg.Table(truststore_list, headings=headings, auto_size_columns=False, col_widths=[10, 25, 65] )], #todo: could not manage to set column size
                          [sg.Button('Ok')],
                        ]
                else:
                    layout2 = [
                          [sg.Text('TrustStore is empty!', size=(20, 1))],
                          [sg.Button('Ok')],
                        ]
                window2 = sg.Window('SeedKeeperTool TrustStore', layout2, icon=self.satochip_icon, finalize=True)  #ok
                event2, values2 = window2.read()    
                window2.close()  
                del window2
            elif event== 'verify_card':
                is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.client.card_verify_authenticity()            
                if is_authentic:
                    txt_result= 'Device authenticated successfully!'
                    txt_color= 'green'
                else:
                    txt_result= ''.join(['Error: could not authenticate the issuer of this card! \n', 
                                                'Reason: ', txt_error , '\n\n',
                                                'If you did not load the card yourself, be extremely careful! \n',
                                                'Contact support(at)satochip.io to report a suspicious device.'])
                    txt_color= 'red'
                
                text_cert_chain= 32*"="+" Root CA certificate: "+32*"="+"\n"
                text_cert_chain+= txt_ca
                text_cert_chain+= "\n"+32*"="+" Sub CA certificate: "+32*"="+"\n"
                text_cert_chain+= txt_subca
                text_cert_chain+= "\n"+32*"="+" Device certificate: "+32*"="+"\n"
                text_cert_chain+= txt_device
                
                layout2 = [
                          [sg.Text(txt_result, text_color= txt_color)],
                          [sg.Multiline(text_cert_chain, key='text_cert_chain', size=(80,20), visible=True)],
                          [sg.Button('Ok')],
                        ]
                window2 = sg.Window('SeedKeeperTool certificate chain validation', layout2, icon=self.satochip_icon, finalize=True)  #ok
                event2, values2 = window2.read()    
                window2.close()  
                del window2
                
            elif event=='Ok' or event=='Cancel' or event==None:
                break
        
        window.close()  
        del window
    
    def help_menu(self):
        logger.debug('In help_menu')
        path = os.path.join(self.pkg_dir, 'help/English.txt')
        with open(path, 'r', encoding='utf-8') as f:
            help_txt = f.read().strip()
        
        languages=['English', 'Français']
        layout = [
            [sg.Text('Select language: ', size=(15, 1)), sg.InputCombo(languages, key='lang', size=(25, 1), enable_events=True)],
            [sg.Multiline(help_txt, key='help_txt', size=(60,20), visible=True)],
            [sg.Button('Ok')]
        ]
        window = sg.Window("Help manual", layout, icon=self.satochip_icon).finalize()
        while True:
            event, values = window.read()  
            if event=='Ok' or event=='Cancel' or event==None:
                break
            if event== 'lang':
                path = os.path.join(self.pkg_dir, 'help/'+values['lang']+'.txt')
                with open(path, 'r', encoding='utf-8') as f:
                    help_txt = f.read().strip()
                window['help_txt'].update(help_txt)
            
        window.close()  
        del window
    
    def mnemonic_wizard(self, card_type):
        # For satochip cards, the user should not be able to generate a new seed, only to import an existing one otherwise no backup is available
        logger.debug('In mnemonic_wizard')
        
        MNEMONIC = Mnemonic(language="english")
        use_passphrase=False
        if card_type== 'SeedKeeper':
            layout = [
                [sg.Text('Label: ', size=(12, 1)), sg.InputText(key='label', size=(40, 1))],
                [sg.Text('Mnemonic type: ', size=(12, 1)), sg.InputCombo(('BIP39 mnemonic' , 'Electrum mnemonic (segwit)', 'Electrum mnemonic (non-segwit)'), key='mnemonic_type', size=(25, 1), enable_events=True)],
                [sg.Text('Mnemonic size: ', size=(12, 1)), sg.InputCombo(('12 words' , '18 words', '24 words'), key='mnemonic_size', size=(25, 1), enable_events=True)],
                [sg.Text('Export rights: ', size=(12, 1)), sg.InputCombo(('Export in plaintext allowed' , 'Export encrypted only'), key='export_rights', size=(25, 1))],
                [sg.Text("")],
                
                [sg.Text("Do you want to create a new mnemonic, or import an existing mnemonic?")],
                [sg.Radio('Create a new mnemonic', 'radio1', key='radio_create', default=False, enable_events=True)], 
                [sg.Radio('I already have a mnemonic', 'radio1', key='radio_restore', default=False, enable_events=True)], 
                [sg.Text('', size=(12, 1), key='mnemonic_prompt', visible=False), sg.Multiline(key='mnemonic', size=(40,3), visible=False, enable_events=True)], 
                [sg.Checkbox('Extends this mnemonic with custom words', key='use_passphrase', default=False, enable_events=True)], 
                [sg.Text('', size=(12, 1), key='passphrase_prompt', visible=use_passphrase), sg.InputText(key='passphrase', visible=use_passphrase)], 
                
                [sg.Button('Submit'), sg.Button('Cancel') ],
                [sg.Text("", key='on_error', text_color='red' )],
            ]
        else: # card_type== 'Satochip':
            layout = [        
                [sg.Text('Enter mnemonic: ', size=(12, 1), key='mnemonic_prompt', visible=False), sg.Multiline(key='mnemonic', size=(40,3), visible=True, enable_events=True)], 
                [sg.Checkbox('Extends this mnemonic with custom words', key='use_passphrase', default=False, enable_events=True)], 
                [sg.Text('', size=(12, 1), key='passphrase_prompt', visible=use_passphrase), sg.InputText(key='passphrase', visible=use_passphrase)], 
                
                [sg.Button('Submit'), sg.Button('Cancel') ],
                [sg.Text("", key='on_error', text_color='red' )],
            ]
            
        window = sg.Window("Create or import mnemonic", layout, icon=self.satochip_icon) 
        
        def check_mnemonic(mnemonic_type, mnemonic):
            nonlocal values
            #logger.debug("Mnemonic: "+str(mnemonic))
            # determine type if needed (e.g. for satochip layout)
            if mnemonic_type=='unknown':
                mnemonic_type= electrum_mnemonic.seed_type(mnemonic)
                if mnemonic_type=='standard':
                    mnemonic_type= 'Electrum mnemonic (non-segwit)'
                elif mnemonic_type=='segwit':
                    mnemonic_type= 'Electrum mnemonic (segwit)'
                else:
                    mnemonic_type= 'BIP39 mnemonic'
                values['mnemonic_type']=mnemonic_type
            
            if (mnemonic_type == 'BIP39 mnemonic'):
                if( not MNEMONIC.check(mnemonic) ):
                    window['on_error'].update(text_color='red' )
                    window['on_error'].update('Mnemonic failed check, try again!')
                    return False
                else:
                    window['on_error'].update(text_color='green' )
                    window['on_error'].update('BIP39 mnemonic ok!')
            elif (mnemonic_type == 'Electrum mnemonic (segwit)'):
                if( electrum_mnemonic.seed_type(mnemonic) != 'segwit'):
                    window['on_error'].update(text_color='red' )
                    window['on_error'].update('Mnemonic failed check, try again!')
                    return False
                else:
                    window['on_error'].update(text_color='green' )
                    window['on_error'].update('Electrum (segwit) mnemonic ok!')
            elif (mnemonic_type == 'Electrum mnemonic (non-segwit)'):
                if( electrum_mnemonic.seed_type(mnemonic) != 'standard'):
                    window['on_error'].update(text_color='red' )
                    window['on_error'].update('Mnemonic failed check, try again!')
                    return False
                else:
                    window['on_error'].update(text_color='green' )
                    window['on_error'].update('Electrum (non-segwit) mnemonic ok!')
            return True
            
        while True:
            event, values = window.read()    
            if event == None or event == 'Cancel':
                break
            
            if event in ['mnemonic_type', 'mnemonic_size']:
                window['mnemonic_prompt'].update('')
                window['mnemonic'].update('')
                window['mnemonic_prompt'].update(visible=False)
                window['mnemonic'].update(visible=False)
                window['radio_create'].update(False) 
                window['radio_restore'].update(False) 
                #window['radio_restore'].reset_group() #nok
                
            if event=='radio_create':
                # strength required
                if ( values['mnemonic_size']=='12 words' ):
                        strength= 128  
                elif ( values['mnemonic_size']=='18 words' ):
                    strength= 192
                elif ( values['mnemonic_size']=='24 words' ):
                    strength= 256
                if ( values['mnemonic_type']=='BIP39 mnemonic' ):
                    mnemonic = MNEMONIC.generate(strength=strength)
                elif ( values['mnemonic_type']=='Electrum mnemonic (segwit)' ):     
                    mnemonic = electrum_mnemonic.Mnemonic('en').make_seed('segwit', num_bits=strength+4)
                elif ( values['mnemonic_type']=='Electrum mnemonic (non-segwit)' ):     
                    mnemonic = electrum_mnemonic.Mnemonic('en').make_seed('standard', num_bits=strength+4)
                window['mnemonic_prompt'].update('Mnemonic created:')
                window['mnemonic'].update(mnemonic)
                window['mnemonic_prompt'].update(visible=True)
                window['mnemonic'].update(visible=True)
                
            elif event=='radio_restore':
                window['mnemonic_prompt'].update('Enter mnemonic: ')
                window['mnemonic'].update('')
                window['mnemonic_prompt'].update(visible=True)
                window['mnemonic'].update(visible=True)
                
            elif event=='use_passphrase':
                use_passphrase= not use_passphrase 
                window['passphrase_prompt'].update('Enter passphrase: ')
                window['passphrase_prompt'].update(visible=use_passphrase)
                window['passphrase'].update(visible=use_passphrase)
                if not use_passphrase:
                    window['passphrase'].update('')
            
            elif event== 'mnemonic':
                mnemonic= values['mnemonic']
                mnemonic_type=  values.get('mnemonic_type', 'unknown')
                check_mnemonic(mnemonic_type, mnemonic)
                
            elif event=='Submit':
                # check label
                if card_type=='SeedKeeper' and len(values['label']) >127:
                    window['on_error'].update(text_color='red' )
                    window['on_error'].update('Label length should be strictly lower than 128!')
                    continue
                # check mnemonic    
                mnemonic_type=  values.get('mnemonic_type', 'unknown') # values['mnemonic_type']
                mnemonic= values['mnemonic']
                if use_passphrase:
                    passphrase= values['passphrase']
                else:
                    passphrase= values['passphrase']=''
                if check_mnemonic(mnemonic_type, mnemonic):
                    # also derive masterseed
                    if mnemonic_type=='BIP39 mnemonic' :
                        values['masterseed']= Mnemonic.to_seed(mnemonic, passphrase)
                    else:  #electrum_mnemonic   
                        values['masterseed']= electrum_mnemonic.Mnemonic.mnemonic_to_seed(mnemonic, passphrase)
                    break
                else:
                    continue
                
        window.close()
        del window
        
        return (event, values)
        
        # print("DEBUG END handler.py ")