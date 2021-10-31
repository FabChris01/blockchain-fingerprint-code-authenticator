from django.urls import path

from . import views


urlpatterns = [
    path('', views.home),
    path('get_data', views.get_data),
]