import traceback
import logging
import json

from web3 import Web3
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from web3.middleware import geth_poa_middleware

logger = logging.getLogger('blocksign')

bcobj = None

class Connector(object):

    def __init__(self):
        self.hostname = 'https://rinkeby.infura.io/v3/28d9dfc7b037474ba748c04581dd217a'
        self.timeout = 30
        self.web3 = self.create_web3()

    def create_web3(self):
        try:
            web3 = Web3(HTTPProvider(self.hostname, request_kwargs={'timeout': self.timeout}))
            web3.middleware_stack.inject(geth_poa_middleware, layer=0)
            return web3
        except:
            logger.error("Error al crear el objeto web3")
            logger.error(traceback.format_exc())
            return None

    def get_w3(self):
        if not self.web3:
            self.web3 = self.create_web3()
        return self.web3

    def get_nonce(self, address):
        try:
            address = Web3.toChecksumAddress(address)
            return self.get_w3().eth.getTransactionCount(address, 'pending')
        except:
            logger.error('Error al obtener el nonce')
            logger.error(traceback.format_exc())

    def create_account(self, passphrase):
        try:
            web3 = self.get_w3()
            account =  web3.eth.account.create()
            pk = account.encrypt(passphrase)
            return account.address, pk
        except:
            logger.error(f'Error al crear la cuenta')
            logger.error(traceback.format_exc())
            return None

    def get_balance(self, address):
        try:
            web3 = self.get_w3()
            return web3.eth.getBalance(address)
        except:
            logger.error(f'Error al obtener el balance de {address}')
            logger.error(traceback.format_exc())

    def call(self, abi, address, field, *args):
        web3 = self.get_w3()
        address = Web3.toChecksumAddress(address)

        myContract = web3.eth.contract(abi=abi, address=address)
        caller = myContract.call()
        value = caller.__getattr__(field)(*args)

        return value

    def create_raw_transact(self, sc_info, gas, gas_price, function_name, from_signuser, *args, nonce=None):
        web3 = self.get_w3()
        abi = json.loads(sc_info.abi)
        address = sc_info.address

        if nonce == None:
            nonce = self.get_nonce(from_signuser.address)

        contract = web3.eth.contract(abi=abi, address=address)
        raw_tx = contract.functions.__getitem__(function_name)(*args).buildTransaction({
            'from': from_signuser.address,
            'gas': gas,
            'gasPrice': web3.toWei(gas_price, 'gwei'),
            'nonce': nonce,
        })
        return raw_tx

    def transact(self, sc_info, gas, gas_price, function_name, from_signuser, *args, nonce=None):
        web3 = self.get_w3()
        pk = web3.eth.account.decrypt(from_signuser.private_key, from_signuser.passphrase)
        account = web3.eth.account.privateKeyToAccount(pk)

        raw_tx = self.create_raw_transact(sc_info, gas, gas_price, function_name, from_signuser, *args, nonce=nonce)

        signed = account.signTransaction(raw_tx)
        tx = web3.eth.sendRawTransaction(signed.rawTransaction).hex()
        return tx

    def is_validated(self, tx_hash):
        web3 = self.get_w3()
        try:
            tx_info = web3.eth.getTransaction(tx_hash)
            if tx_info['blockNumber'] != None:
                return True
        except:
            pass
        return False


def get_bcobj():
    global bcobj
    if bcobj:
        return bcobj
    else:
        logger.info('No existe, creando obj para la conexion con la blockchain')
        bcobj = Connector()
        return bcobj
