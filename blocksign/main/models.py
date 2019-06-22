from django.db import models
from django.contrib.auth.models import User

class SignUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    address = models.CharField(max_length=42)
    passphrase = models.CharField(max_length=30, default="aabbcc11")
    private_key = models.TextField(null=True, blank=True)
    avatar = models.ImageField(upload_to='user/%Y_%m', null=True, blank=True)

    def __str__(self):
        return f'{self.user.email}- {self.address}'

class DocumentStatus(models.Model):
    name = models.CharField(max_length=66, unique=True)

    def __str__(self):
        return f'{self.name}'

class Document(models.Model):
    hash = models.CharField(max_length=66, primary_key=True)
    minter = models.ForeignKey(SignUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    document = models.FileField(upload_to='documents/%Y_%m', verbose_name='Documento')
    tx_id = models.CharField(max_length=66, unique=True)
    status = models.ForeignKey(DocumentStatus, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    def __str__(self):
        return f'{self.name} - {self.minter.user.username}'

class CollaboratorDocument(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    collaborator = models.ForeignKey(SignUser, on_delete=models.CASCADE)
    tx_id = models.CharField(max_length=66, null=True)
    timestamp = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    status = models.CharField(default="Pending", max_length=44)

    class Meta:
        unique_together = ('document', 'collaborator')

    def __str__(self):
        return f'{self.document.name} - {self.collaborator.user.email}'

class SCInfo(models.Model):
    name = models.CharField(max_length=80, primary_key=True)
    address = models.CharField(max_length=42)
    abi = models.TextField()

    def __str__(self):
        return f'{self.name} -> {self.address}'

class BCValue(models.Model):
    chain_id = models.IntegerField(default=1)
    gas = models.IntegerField(default=4500000)
    gas_price = models.IntegerField(default=45)

    def __str__(self):
        return f'ChainId: {self.chain_id}, gas: {self.gas}, gas_price: {self.gas_price}'
