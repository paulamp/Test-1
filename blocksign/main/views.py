import datetime
import logging
import traceback
import base64

from django.shortcuts import render
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
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
        print(username)
        print(password)
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user:
                print("login")
                login(request, user)
                return HttpResponseRedirect(reverse('home'))
        messages.error(request, 'Credenciales incorrectos')
    return render(request, 'login.html')

def invitation_email_view(request, token, user_id):
    decoded_user_id = urlsafe_base64_decode(user_id).decode()
    try:
        user = User.objects.get(pk = decoded_user_id)
        logger.info(f"Usuario encontrado {user.username}")
    except:
        return HttpResponseRedirect(reverse('root'))
    logout(request)
    if user.first_name:
        logger.info("Esta usuario ya estaba registrado")
        return HttpResponseRedirect(reverse('root'))
    print(default_token_generator.check_token(user, token))
    if user and default_token_generator.check_token(user, token):
        logger.info(f"Necesita registrarse {user.username}")
        context = {'email': user.email}
        return render(request, 'register_user.html', context)
    return HttpResponseRedirect(reverse('root'))

def register_view(request):
    if request.method == "POST":
        first_name = request.POST.get('name', "")
        last_name = request.POST.get('last_name', "")
        email = request.POST.get('email', "")
        password = request.POST.get('password', "")
        password_2 = request.POST.get('password_2', "")
        is_invitation = request.POST.get('is_invitation', "")
        if password != password_2:
            messages.warning(request, "Las contraseñas no coinciden")
            return render(request, 'login.html')
        if not is_invitation:
            try:
                User.objects.get(username=email)
                messages.warning(request, "Este email ya esta registrado")
                return render(request, 'login.html')
            except:
                logger.info(f"Registrando al usuario {email}")
        sign_user = get_signUser_or_create(email)
        sign_user.user.first_name = first_name
        sign_user.user.last_name = last_name
        sign_user.user.set_password(password)
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
    show_col = False
    fecha_inicio_mis = request.POST.get("fecha_inicio_mis", '')
    fecha_fin_mis = request.POST.get("fecha_fin_mis", '')
    name_doc_mis = request.POST.get("name_doc_mis")
    estado_doc_mis = request.POST.get("estado_doc_mis")

    fecha_inicio_col = request.POST.get("fecha_inicio_col", '')
    fecha_fin_col = request.POST.get("fecha_fin_col", '')
    name_doc_col = request.POST.get("name_doc_col")
    estado_doc_col = request.POST.get("estado_doc_col")

    q_filter_mis = {'minter': request.user.signuser}
    if fecha_inicio_mis:
        q_filter_mis['timestamp__gte'] = string_to_date(fecha_inicio_mis)
    if fecha_fin_mis:
        q_filter_mis['timestamp__lte'] = string_to_date(fecha_fin_mis)
    if name_doc_mis:
        q_filter_mis['name__contains'] = name_doc_mis
    if estado_doc_mis:
        estado_doc_mis = int(estado_doc_mis)
        q_filter_mis['status__id'] = estado_doc_mis

    q_filter_col = {}
    if fecha_inicio_col:
        show_col = True
        q_filter_col['timestamp__gte'] = string_to_date(fecha_inicio_col)
    if fecha_fin_col:
        show_col = True
        q_filter_col['timestamp__lte'] = string_to_date(fecha_fin_col)
    if name_doc_col:
        show_col = True
        q_filter_col['name__contains'] = name_doc_col
    if estado_doc_col:
        show_col = True
        estado_doc_col = int(estado_doc_col)
        q_filter_col['status__id'] = estado_doc_col

    documents = Document.objects.filter(**q_filter_mis)

    colaborations = CollaboratorDocument.objects.filter(collaborator=request.user.signuser).values('document__hash')
    q_filter_col['hash__in'] = colaborations
    colaboration_documents = Document.objects.filter(**q_filter_col)
    estados_doc = DocumentStatus.objects.all()
    context = {
        'documents': documents,
        'doc_colaborations': colaboration_documents,
        'estados_doc':estados_doc,
        'estado_selected_mis': estado_doc_mis,
        'estado_selected_col': estado_doc_col,
        'fecha_inicio_mis' : fecha_inicio_mis,
        'fecha_fin_mis' : fecha_fin_mis,
        'name_doc_mis' : name_doc_mis,
        'fecha_inicio_col' : fecha_inicio_col,
        'fecha_fin_col' : fecha_fin_col,
        'name_doc_col' : name_doc_col,
        'show_col': show_col,

    }
    return render(request, 'home.html', context)

@login_required
def document_detail(request, hash):
    try:
        document = Document.objects.get(hash=hash)
        collaborators = CollaboratorDocument.objects.filter(document=document)
        r_address = request.user.signuser.address
        is_collaborator = collaborators.filter(collaborator__address=r_address).exists()
        comments = CollaboratorAction.objects.filter(document=document).exclude(comment="Validated").order_by('-timestamp')
        if r_address != document.minter.address and not is_collaborator:
            return render(request, 'doc_detail.html')
        if r_address == document.minter.address:
            #CollaboratorAction.objects.filter(document=document).update(view=True)
            pass
        context = {
            'document':document,
            'collaborators': collaborators,
            'is_collaborator':is_collaborator,
            'comments':comments
        }
        if request.method == 'POST':
            collaborator_email = request.POST.get("collaborator_email", '')
            if not collaborator_email:
                logger.info("No se ha especificado el email del colaborador")
                messages.warning(request, "No se ha especificado el email del colaborador")
                return render(request, 'doc_detail.html', context)
            if collaborator_email == request.user.email:
                logger.info("No te puedes añadir de colaborador a ti mismo")
                messages.warning(request, "No te puedes añadir de colaborador a ti mismo")
                return render(request, 'doc_detail.html', context)
            status = None
            if document.status.name in ["Confirmado" ,"Rechazado"]:
                try:
                    status = DocumentStatus.objects.get(name="Con colaboradores")
                except:
                    messages.warning(request, "No se ha encontrado el estado del documento")
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
                exists = bcobj.call(sc_sign.abi, sc_sign.address, "hashValidatorUser", b_hash, sign_user.address)
            except:
                messages.warning(request, "Error al comprobar si existe este colaborador en la BC")
                logger.error(traceback.format_exc())
                return render(request, 'doc_detail.html', context)
            if exists:
                messages.warning(request, f"Este colaborador ya se encuentra asociado a este documento")
                return render(request, 'doc_detail.html', context)
            tx_id = bcobj.transact(sc_sign, bc_values.gas, bc_values.gas_price, "addValidatorUser", request.user.signuser, b_hash, sign_user.address)
            logger.info(f"Added Collaborator Tx -> {tx_id}")
            validated_email(sign_user, request.user)
            new_collaborator = CollaboratorDocument()
            new_collaborator.document = document
            new_collaborator.collaborator = sign_user
            new_collaborator.tx_id = tx_id
            new_collaborator.save()
            if status:
                document.status = status
                document.save()
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
        logger.error(traceback.format_exc())
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
        try:
            status = DocumentStatus.objects.get(name="Pendiente")
        except:
            messages.error(request, "No se ha encontrado el estado 'Pendiente' en la app")
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
        new_document.name = filename #coge el nombre
        new_document.document = filename #gurada el documento
        new_document.tx_id = tx_id
        new_document.status = status
        new_document.save()
        messages.success(request, "Documento registrado con éxito")
    return render(request, 'upload.html')

@login_required
def profile_view(request):
    if request.method == "POST":
        if 'avatar' in request.FILES:
            avatar = request.FILES['avatar']
            request.user.signuser.avatar = avatar
            request.user.signuser.save()
    return render(request, 'profile.html')

@login_required
def add_comment_view(request):
    if request.method == "POST":
        hash = request.POST.get('hash', None)
        if not hash:
            return HttpResponseRedirect(reverse('home'))
        try:
            document = Document.objects.get(hash=hash)
        except:
            messages.error(request, "Documento no encontrado en la aplicación")
            return HttpResponseRedirect(reverse('home'))
        try:
            sc_sign = SCInfo.objects.get(name="Sign")
        except:
            messages.error(request, "No se ha encontrado información del SC")
            return HttpResponseRedirect(reverse('doc_details', kwargs={'hash':hash}))
        bc_values = BCValue.objects.first()
        if not bc_values:
            messages.error(request, "No se ha encontrado información sobre la BC")
            return HttpResponseRedirect(reverse('doc_details', kwargs={'hash':hash}))
        comment = request.POST.get('comment_back', None)
        if not comment:
            return HttpResponseRedirect(reverse('doc_details', kwargs={'hash':hash}))

        status_doc = get_doc_status(document, request.user.signuser, comment)
        if not status_doc:
            messages.error(request, "No se ha encontrado el estado del documento")
            return HttpResponseRedirect(reverse('doc_details', kwargs={'hash':hash}))

        bcobj = get_bcobj()
        tx_id = bcobj.transact(sc_sign, bc_values.gas, bc_values.gas_price, "addValidationUser", request.user.signuser, hash, request.user.signuser.address, comment)
        logger.info(f"Tx -> {tx_id}")
        new_action = CollaboratorAction()
        new_action.document = document
        new_action.collaborator = request.user.signuser
        new_action.tx_id = tx_id
        new_action.comment = comment
        new_action.save()
        document.status = status_doc
        document.save()
        return HttpResponseRedirect(reverse('doc_details', kwargs={'hash':hash}))
    return HttpResponseRedirect(reverse('home'))

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
        print(f"Buscando el user {email}")
        user = User.objects.get(email=email)
    except:
        user = User()
        user.username = email
        user.email = email
        user.save()
    return user

def get_doc_status(document, collaborator, comment):
    status_name = "Con observaciones"
    if comment == "Validated":
        collaborations = CollaboratorDocument.objects.filter(document=document).exclude(collaborator=collaborator)
        all_last_comments = [comment]
        for collaboration in collaborations:
            last_comment = get_last_comment(collaboration.collaborator)
            if last_comment:
                all_last_comments.append(last_comment)
        no_repeats = set(all_last_comments)
        if len(no_repeats) == 1:
            if "Validated" in no_repeats:
                status_name = "Validado"
    try:
        return DocumentStatus.objects.get(name = status_name)
    except:
        logger.error(f"Estado {status_name} no encontrado")
        return None

def get_last_comment(collaborator):
    last_comment = CollaboratorAction.objects.filter(collaborator=collaborator).order_by('-timestamp')
    if last_comment:
        return last_comment[0]
    return None

def string_to_date(date_str):
    return datetime.datetime.strptime(date_str, '%d/%m/%Y').date()
