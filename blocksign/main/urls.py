from django.urls import path
from django.conf.urls.static import static
from blocksign import settings
from . import views

urlpatterns = [
    path('', views.root_view, name='root'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('register', views.register_view, name='register'),
    path('home', views.home_view, name='home'),
    path('home/doc_details/<str:hash>', views.document_detail, name='doc_details'),
    path('add_comment', views.add_comment_view, name='add_comment'),
    path('upload', views.upload_view, name='upload'),
    path('profile', views.profile_view, name='profile'),
    path('balance', views.balance_view, name='balance'),
    path('invitation_email/<str:token>/<str:user_id>', views.invitation_email_view, name='invitation_email'),

]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
