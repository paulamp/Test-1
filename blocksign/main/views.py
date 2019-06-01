import datetime
import logging
import traceback

from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from main.bc_connector import get_bcobj
from main.models import *
from main.emails import validated_email

logger = logging.getLogger('blocksign')

def root_view(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse('home'))
    return HttpResponseRedirect(reverse('login'))

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return HttpResponseRedirect(reverse('home'))
        messages.error(request, 'Credenciales incorrectos')
    return render(request, 'login.html')

def register_view(request):
    if request.method == "POST":
        fist_name = request.POST.get('name', "")
        last_name = request.POST.get('last_name', "")
        email = request.POST.get('email', "")
        password = request.POST.get('password', "")
        password_2 = request.POST.get('password_2', "")
        if password != password_2:
            messages.warning(request, "Las contraseñas no coinciden")
            return render(request, 'login.html')
        logger.info(f"Registrando al usuario {email}")
        sign_user = get_signUser_or_create(email)
        if sign_user:
            messages.warning(request, "Este email ya esta registrado")
            return render(request, 'login.html')
        sign_user.user.fist_name = fist_name
        sign_user.user.last_name = last_name
        sign_user.user.password = password
        sign_user.user.save()
        messages.success(request, "Registro realizado con éxito")
    return HttpResponseRedirect(reverse('root'))

def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse('root'))

@login_required
def balance_view(request):
    try:
        bcobj = get_bcobj()
        balance = bcobj.get_balance(request.user.signuser.address)
        balance_to_eth = float(balance)/float(1000000000000000000)
        balance = round(balance_to_eth,2)
    except:
        logger.error("Error al obtener el balance")
        balance =  0
    return JsonResponse({'balance':balance})

@login_required
def home_view(request):
    documents = Document.objects.filter(minter=request.user.signuser)
    context = {
        'documents': documents
    }
    return render(request, 'home.html', context)

@login_required
def document_detail(request, hash):
    try:
        document = Document.objects.get(hash=hash)
        collaborators = CollaboratorDocument.objects.filter(document=document)
        context = {
            'document':document,
            'collaborators': collaborators
        }
        if request.method == 'POST':
            collaborator_email = request.POST.get("collaborator_email", '')
            if not collaborator_email:
                logger.info("No se ha especificado el email del colaborador")
                messages.warning(request, "No se ha especificado el email del colaborador")
                return render(request, 'doc_detail.html', context)
            sign_user = get_signUser_or_create(collaborator_email)
            sc_sign = SCInfo.objects.get(name="Sign")
            bc_values = BCValue.objects.first()
            if not bc_values:
                messages.error(request, "No se ha encontrado información sobre la BC")
                return render(request, 'doc_detail.html', context)
            b_hash = bytes.fromhex(hash)
            bcobj = get_bcobj()
            try:
                logger.info("Comprobando existencia del colaborador en el documento en la BC ...")
                exists = bcobj.call(sc_sign.abi, sc_sign.address, "hashValidatorUser", b_hash, sc_sign.address)
            except:
                messages.warning(request, "Error al comprobar si existe este colaborador en la BC")
                logger.error(traceback.format_exc())
                return render(request, 'doc_detail.html', context)
            if exists:
                messages.warning(request, f"Este colaborador ya se encuentra asociado a este documento")
                return render(request, 'doc_detail.html', context)
            tx_id = bcobj.transact(sc_sign, bc_values.gas, bc_values.gas_price, "addValidatorUser", request.user.signuser, b_hash, sign_user.address)
            logger.info(f"Added Collaborator Tx -> {tx_id}")
            new_collaborator = CollaboratorDocument()
            new_collaborator.document = document
            new_collaborator.collaborator = sign_user
            new_collaborator.tx_id = tx_id
            new_collaborator.save()
            validated_email(sign_user)
            messages.success(request, "colaborador añadido con éxito")
        return render(request, 'doc_detail.html', context)
    except Document.DoesNotExist:
        messages.error(request, "No se ha encontrado este hash en el sistema")
        return render(request, 'doc_detail.html')
    except SCInfo.DoesNotExist:
        messages.error(request, "No se ha encontrado información del SC")
        return render(request, 'doc_detail.html')
    except:
        messages.error(request, "Ha ocurrido un error, contacte con el administrador")
        return render(request, 'doc_detail.html')



@login_required
def upload_view(request):
    if request.method == 'POST':
        filename = None
        hash = request.POST.get('hash', None)
        if 'file' in request.FILES:
            filename = request.FILES['file']
        if not filename:
            messages.error(request, "Se debe especificar un documento")
            return render(request, 'upload.html')
        try:
            sc_sign = SCInfo.objects.get(name="Sign")
        except:
            messages.error(request, "No se ha encontrado información del SC")
            return render(request, 'upload.html')
        bc_values = BCValue.objects.first()
        if not bc_values:
            messages.error(request, "No se ha encontrado información sobre la BC")
            return render(request, 'upload.html')
        b_hash = bytes.fromhex(hash)
        bcobj = get_bcobj()
        try:
            logger.info("Comprobando existencia del documento en la BC ...")
            exists = bcobj.call(sc_sign.abi, sc_sign.address, "hashDocuments", b_hash)
        except:
            messages.error(request, "Error al comprobar si existe en la BC")
            logger.error(traceback.format_exc())
            return render(request, 'upload.html')

        if exists:
            owner = bcobj.call(sc_sign.abi, sc_sign.address, "hashOwner", b_hash)
            try:
                user = SignUser.objects.get(address=owner)
                messages.warning(request, f"Este documento ya lo ha registrado {user.email} en la BC")
            except:
                messages.warning(request, f"Este documento ya se encuentra registrado en la BC")
            return render(request, 'upload.html')

        tx_id = bcobj.transact(sc_sign, bc_values.gas, bc_values.gas_price, "newDocument", request.user.signuser, b_hash)
        logger.info(f"{filename} Tx -> {tx_id}")
        new_document = Document()
        new_document.hash = hash
        new_document.minter = request.user.signuser
        new_document.name = filename
        new_document.tx_id = tx_id
        new_document.save()
        messages.success(request, "Documento registrado con éxito")
    return render(request, 'upload.html')

@login_required
def profile_view(request):
    if request.user.is_authenticated:
        return render(request, 'profile.html')
    return HttpResponseRedirect(reverse('root'))

def about_view(request):
    return render(request, 'about.html')

#############
##FUNCTIONS##
#############

def get_signUser_or_create(email):
    user = get_user_or_create(email)
    try:
        sign_user = SignUser.objects.get(user=user)
    except:
        sign_user = SignUser()
        bcobj = get_bcobj()
        passphrase = "aabbcc11"
        account = bcobj.create_account(passphrase)
        sign_user.user = user
        sign_user.passphrase = passphrase
        sign_user.address = account[0]
        sign_user.private_key = account[1]
        sign_user.save()
    return sign_user


def get_user_or_create(email):
    try:
        print(f"busanco el user {email}")
        user = User.objects.get(email=email)
    except:
        user = User()
        user.username = email
        user.email = email
        user.save()
    return user
