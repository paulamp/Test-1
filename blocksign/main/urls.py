from django.urls import path
from . import views

urlpatterns = [
    path('', views.root_view, name='root'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('register', views.register_view, name='register'),
    path('home', views.home_view, name='home'),
    path('home/doc_details/<str:hash>', views.document_detail, name='doc_details'),
    path('upload', views.upload_view, name='upload'),
    path('profile', views.profile_view, name='profile'),
    path('about', views.about_view, name='about'),
    path('balance', views.balance_view, name='balance'),

]
