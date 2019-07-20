import logging
import time

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

from main.models import BCValue, SCInfo, DocumentStatus

logger = logging.getLogger('blocksign')

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument(
            '--address',
            help = 'El address del SC',
        )

    def handle(self, *args, **options):
        address = ""
        if 'address' in options:
            address = options['address']
        if not address:
            logger.error("No se ha especificado address")
        init_superuser()
        init_bc_value()
        init_sc(address)
        init_documents_status()


def init_superuser():
    username = "admin"
    password = "a12341234"
    try:
        User.objects.get(username=username)
    except:
        user = User.objects.create_user(username=username, password=password)
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save()

def init_bc_value():
    BCValue.objects.all().delete()
    bc_value = BCValue()
    bc_value.gas = 6000000
    bc_value.gas_price = 41
    bc_value.save()

def init_sc(address):
    SCInfo.objects.all().delete()
    sc = SCInfo()
    sc.name = "Sign"
    sc.address = address
    sc.abi = '[{"constant": true,"inputs": [{"name": "","type": "bytes32"}],"name": "hashDocuments","outputs": [{"name": "","type": "bool"}],"payable": false,"stateMutability": "view","type": "function","signature": "0x13fa2c33"},{"constant": true,"inputs": [{"name": "","type": "bytes32"},{"name": "","type": "address"}],"name": "documentComments","outputs": [{"name": "","type": "string"}],"payable": false,"stateMutability": "view","type": "function","signature": "0x1e1f3a76"},{"constant": true,"inputs": [{"name": "","type": "bytes32"},{"name": "","type": "address"}],"name": "hashValidatorUser","outputs": [{"name": "","type": "bool"}],"payable": false,"stateMutability": "view","type": "function","signature": "0x24cff8a5"},{"constant": true,"inputs": [{"name": "","type": "bytes32"},{"name": "","type": "uint256"}],"name": "documentValidators","outputs": [{"name": "","type": "address"}],"payable": false,"stateMutability": "view","type": "function","signature": "0x2ee69a47"},{"constant": true,"inputs": [{"name": "","type": "bytes32"}],"name": "hashOwner","outputs": [{"name": "","type": "address"}],"payable": false,"stateMutability": "view","type": "function","signature": "0x55d53b6d"},{"anonymous": false,"inputs": [{"indexed": false,"name": "hashDocument","type": "bytes32"},{"indexed": false,"name": "minter","type": "address"}],"name": "DocumentAdded","type": "event","signature": "0xdbfa39e1690eb55308046a0453096b664b994ffbbd01e9a81be622d3ce8d8166"},{"anonymous": false,"inputs": [{"indexed": false,"name": "hashDocument","type": "bytes32"},{"indexed": false,"name": "user","type": "address"}],"name": "NewInvitation","type": "event","signature": "0x1ad3d870cac386a63145d4fdf6f7dee8a5d9b7c7a04d8b74180f2cc48b47b4ce"},{"anonymous": false,"inputs": [{"indexed": false,"name": "hashDocument","type": "bytes32"},{"indexed": false,"name": "user","type": "address"},{"indexed": false,"name": "comment","type": "string"}],"name": "ActionAdded","type": "event","signature": "0x8e859c406054c5af73137946ffde0bfdfff4d4cb1d9919f29c4e95bdb76ad50e"},{"constant": false,"inputs": [{"name": "hashDocument","type": "bytes32"}],"name": "newDocument","outputs": [],"payable": false,"stateMutability": "nonpayable","type": "function","signature": "0x2847a7af"},{"constant": false,"inputs": [{"name": "hashDocument","type": "bytes32"},{"name": "user","type": "address"}],"name": "addValidatorUser","outputs": [],"payable": false,"stateMutability": "nonpayable","type": "function","signature": "0xe9eb367a"},{"constant": false,"inputs": [{"name": "hashDocument","type": "bytes32"},{"name": "user","type": "address"},{"name": "comment","type": "string"}],"name": "addValidationUser","outputs": [],"payable": false,"stateMutability": "nonpayable","type": "function","signature": "0xd71b08d2"}]'
    sc.save()


def init_documents_status():
    DocumentStatus.objects.all().delete()
    new_status = DocumentStatus()
    new_status.name = "Pendiente"
    new_status.save()
    new_status = DocumentStatus()
    new_status.name = "Confirmado"
    new_status.save()
    new_status = DocumentStatus()
    new_status.name = "Rechazado"
    new_status.save()
    new_status = DocumentStatus()
    new_status.name = "Con colaboradores"
    new_status.save()
    new_status = DocumentStatus()
    new_status.name = "Validado"
    new_status.save()
    new_status = DocumentStatus()
    new_status.name = "Con observaciones"
    new_status.save()
